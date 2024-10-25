/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include "vole.h"
#include "vbb.h"
#include "aes.h"
#include "utils.h"
#include "random_oracle.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

int ChalDec(const uint8_t* chal, unsigned int i, unsigned int k0, unsigned int t0, unsigned int k1,
            unsigned int t1, uint8_t* chalout) {
  if (i >= t0 + t1) {
    return 0;
  }

  unsigned int lo;
  unsigned int hi;
  if (i < t0) {
    lo = i * k0;
    hi = ((i + 1) * k0);
  } else {
    unsigned int t = i - t0;
    lo             = (t0 * k0) + (t * k1);
    hi             = (t0 * k0) + ((t + 1) * k1);
  }

  assert(hi - lo == k0 || hi - lo == k1);
  for (unsigned int j = lo; j < hi; ++j) {
    // set_bit(chalout, i - lo, get_bit(chal, i));
    chalout[j - lo] = ptr_get_bit(chal, j);
  }
  return 1;
}

void partial_vole_commit_cmo(const uint8_t* rootKey, const uint8_t* iv,
                             unsigned int col_start, unsigned int col_end, unsigned int row_start, unsigned int row_end,
                             sign_vole_mode_ctx_t vole_mode, const faest_paramset_t* params) {

  unsigned int sd_expand_len = row_end-row_start;
  unsigned int ellhat = params->faest_param.l + params->faest_param.lambda * 2 + UNIVERSAL_HASH_B_BITS;
  printf("sd_expand_len is of length: %d\n", sd_expand_len);

  //uint8_t incremented_iv[16];
  //// Seed expansion needs to be offset by the rowStart
  //if (rowStart > 0) {
  //  memcpy(incremented_iv, iv, sizeof(incremented_iv));
  //  // TODO: Handle EM
  //  aes_iv_add(incremented_iv, rowStart/128); // TODO: replace with AES state size (128 bit)
  //  sd_expand_len = rowEnd-rowStart + (rowStart % 128) // TODO: replace with AES state size (128 bit)
  //}

  unsigned int lambda       = params->faest_param.lambda;
  unsigned int lambda_bytes = lambda / 8;
  unsigned int sd_expand_len_bytes = (sd_expand_len + 7) / 8;
  unsigned int ellhat_bytes = (ellhat + 7) / 8;
  unsigned int tau          = params->faest_param.tau;
  unsigned int tau0         = params->faest_param.t0;
  unsigned int k0           = params->faest_param.k0;
  unsigned int k1           = params->faest_param.k1;
  unsigned int max_depth    = MAX(k0, k1);

  uint8_t* expanded_keys = malloc(tau * lambda_bytes);
  prg(rootKey, iv, expanded_keys, lambda, lambda_bytes * tau);
  uint8_t* path = malloc(lambda_bytes * max_depth * 2);

  H1_context_t hcom_ctx;
  H1_context_t com_ctx;
  uint8_t* h = NULL;
  if (vole_mode.mode != EXCLUDE_U_HCOM_C) {
    h = malloc(lambda_bytes * 2);
    H1_init(&hcom_ctx, lambda);
  }

  // STEP 1: To commit to [col_start,col_end] we first compute which trees we need to consider
  unsigned int depth_tau_0     = tau0 * k0;

  unsigned int k0_trees_begin  = (col_start < depth_tau_0) ? col_start / k0 : tau0;
  unsigned int k1_trees_begin  = (col_start < depth_tau_0) ? 0 : (col_start - depth_tau_0) / k1;
  unsigned int k0_trees_end    = (col_end < depth_tau_0)   ? (col_end + (k0-1)) / k0 : tau0; // ceiled
  unsigned int k1_trees_end    = (col_end < depth_tau_0)   ? 0 : (col_end - depth_tau_0 + (k1-1)) / k1;  // ceiled

  unsigned int tree_start = k0_trees_begin+k1_trees_begin;
  unsigned int tree_end   = k0_trees_end+k1_trees_end;

  // Compute the cummulative sum of the tree depths until the requested start
  unsigned int col_progress = k0 * k0_trees_begin + k1 * k1_trees_begin;
  
  bool debug = false;
  bool has_printed = false;

  for (unsigned int t = tree_start; t < tree_end; t++) {
    bool is_first_tree      = (t == 0);
    unsigned int tree_depth = t < tau0 ? k0 : k1;

    // col_cache_offset is used to compute the index we should write v to relative to our cache
    unsigned int col_cache_offset  = (col_progress > col_start) ? col_progress - col_start : 0; // (i.e. MAX(col_progress-col_start, 0))
    // [t_col_start, t_col_end] is columns of v that t provides (capped by requested col_start/col_end)
    unsigned int t_col_start    = MAX(col_progress, col_start); 
    unsigned int t_col_end      = MIN(col_end, col_progress+tree_depth);

    // (Setup for STEP 2)
    const unsigned int num_seeds = 1 << tree_depth;
    uint8_t sd[MAX_LAMBDA_BYTES];
    uint8_t com[2*MAX_LAMBDA_BYTES];
    uint8_t* r = malloc(ellhat_bytes);
    uint8_t* truncated_r = malloc(sd_expand_len_bytes); // temp

    uint8_t* u_ptr = NULL;
    if (vole_mode.mode != EXCLUDE_U_HCOM_C) {
      H1_init(&com_ctx, lambda);
      u_ptr = is_first_tree ? vole_mode.u : vole_mode.c + (t - 1) * ellhat_bytes;
      memset(u_ptr, 0, ellhat_bytes);
    }
    if (vole_mode.mode != EXCLUDE_V) {
      unsigned int t_column_count = t_col_end-t_col_start;
      memset(vole_mode.v+(col_cache_offset*sd_expand_len_bytes), 0, t_column_count*sd_expand_len_bytes);
    }
    
    vec_com_t vec_com;
    vector_commitment(expanded_keys + t * lambda_bytes, lambda, tree_depth, path, &vec_com);

    // STEP 2: For this tree, extract all seeds and commitments and compute according to the VOLE-mode
    for (unsigned int i = 0; i < num_seeds; i++) {
      extract_sd_com(&vec_com, iv, lambda, i, sd, com);
      prg(sd, iv, r, lambda, ellhat_bytes); // Seed expansion
      memcpy(truncated_r, ((uint8_t*) r + row_start/8), sd_expand_len_bytes);
      if (!has_printed && debug) {
        has_printed = true;
        printf("Seed expanded to: ");
        for (unsigned int W = 0; W < ellhat_bytes; W++) {
          printf("%d ", r[W]);
        }
        printf("\n");
        printf("With truncated: ");
        for (unsigned int W = 0; W < sd_expand_len_bytes; W++) {
          printf("%d ", truncated_r[W]);
        }
        printf("\n");
      }

      if (vole_mode.mode != EXCLUDE_U_HCOM_C) {
        int factor_32 = ellhat_bytes / 4;
        H1_update(&com_ctx, com, lambda_bytes * 2);
        xor_u32_array((uint32_t*)u_ptr, (uint32_t*)r, (uint32_t*)u_ptr, factor_32);
        xor_u8_array(u_ptr + factor_32 * 4, r + factor_32 * 4, u_ptr + factor_32 * 4,
                    ellhat_bytes - factor_32 * 4);
      }
      if (vole_mode.mode != EXCLUDE_V) {
        for (unsigned int j = t_col_start; j < t_col_end; j++) {
          // Instead of writing v_j at V[j], use the v_cache_offset
          uint8_t* write_idx = (vole_mode.v+(j-t_col_start+col_cache_offset) * sd_expand_len_bytes);
          unsigned int t_v = j-col_progress; // That is; t_v reflects the current v \in [0, depth] in tree t
          // Apply r if the i/2^t_v is odd
          if ((i >> t_v) & 1) {
            int factor_32 = sd_expand_len_bytes / 4;
            xor_u32_array((uint32_t*) write_idx, (uint32_t*)truncated_r, (uint32_t*) write_idx, factor_32);
            xor_u8_array(write_idx + factor_32 * 4, truncated_r + factor_32 * 4, write_idx + factor_32 * 4,
                        sd_expand_len_bytes - factor_32 * 4);
          }
          if (j == 0 && debug) {
            printf("Memory at write_idx for col %d, seed: %d: ", j, i);
            for (unsigned int W = 0; W < sd_expand_len_bytes; W++) {
              printf("%d ", write_idx[W]);
            }
            printf("\n");
          }
        }
      }
    }

    free(r);
    free(truncated_r);

    if (vole_mode.mode != EXCLUDE_U_HCOM_C) {
      if (!is_first_tree) {
        xor_u8_array(vole_mode.u, u_ptr, u_ptr, ellhat_bytes); // Correction values
      }
      H1_final(&com_ctx, h, lambda_bytes * 2);
      H1_update(&hcom_ctx, h, lambda_bytes * 2);
    }

    col_progress += tree_depth;
  }

  if (vole_mode.mode != EXCLUDE_U_HCOM_C) {
    H1_final(&hcom_ctx, vole_mode.hcom, lambda_bytes * 2);
    free(h);
  }

  free(expanded_keys);
  free(path);
}

void partial_vole_commit_rmo(const uint8_t* rootKey, const uint8_t* iv,
                             unsigned int start, unsigned int len, 
                             const faest_paramset_t* params, uint8_t* v, vbb_t* vbb_temp) {
  unsigned int lambda       = params->faest_param.lambda;
  unsigned int lambda_bytes = lambda / 8;
  unsigned int ell_hat =
      params->faest_param.l + params->faest_param.lambda * 2 + UNIVERSAL_HASH_B_BITS;
  unsigned int ellhat_bytes = (ell_hat + 7) / 8;
  unsigned int tau          = params->faest_param.tau;
  unsigned int tau0         = params->faest_param.t0;
  unsigned int k0           = params->faest_param.k0;
  unsigned int k1           = params->faest_param.k1;
  unsigned int max_depth    = MAX(k0, k1);

  unsigned int end = start + len;

  // temp fix: store row_length_bytes in the vbb so it knows the cmo column length to transpose
  vbb_temp->row_length_bytes = (len + 7)/8;
  printf("vbb_temp->row_length_bytes: %d\n", (len + 7)/8);

  printf("Forwarding rmo -> cmo call with with cols: [%d, %d) rows: [%d, %d) - ellhat is: %d\n", 0, lambda, start, end, ell_hat);
  partial_vole_commit_cmo(rootKey, iv, 0, lambda, start, end, vole_mode_v(v), params);
  return;

  uint8_t* expanded_keys = malloc(tau * lambda_bytes);
  uint8_t * sd           = malloc(lambda_bytes);
  uint8_t* com           = malloc(lambda_bytes * 2);
  uint8_t* r             = malloc(ellhat_bytes);
  uint8_t* path          = malloc(lambda_bytes * max_depth);

  vec_com_t vec_com;
  memset(v, 0, ((size_t)len) * (size_t)lambda_bytes);
  prg(rootKey, iv, expanded_keys, lambda, lambda_bytes * tau);
  
  unsigned int col_idx = 0;
  for (unsigned int t = 0; t < tau; t++) {
    unsigned int depth = t < tau0 ? k0 : k1;

    vector_commitment(expanded_keys + t * lambda_bytes, lambda, depth, path, &vec_com);
    
    unsigned int byte_offset = (col_idx / 8);
    unsigned int bit_offset  = (col_idx % 8);
    
    const unsigned int num_instances = 1 << depth;
    for (unsigned int i = 0; i < num_instances; i++) {
      extract_sd_com(&vec_com, iv, lambda, i, sd, com);
      prg(sd, iv, r, lambda, ellhat_bytes);

      for (unsigned int row_idx = start; row_idx < end; row_idx++) {
        unsigned int byte_idx = row_idx / 8;
        unsigned int bit_idx  = row_idx % 8;
        // bit is r[row_idx]
        uint8_t bit           = (r[byte_idx] >> (bit_idx)) & 1;
        if (bit == 0) {
          continue;
        }
        unsigned int write_idx = (row_idx-start) * lambda_bytes + byte_offset;
        unsigned int amount    = (bit_offset + depth + 7) / 8;
        // Avoid carry by breaking into two steps
        v[write_idx + 0] ^= i << bit_offset;
        for (unsigned int j = 1; j < amount; j++) {
          v[write_idx + j] ^= i >> (j * 8 - bit_offset);
        }
      }
    }

    col_idx += depth;
  }

  free(sd);
  free(com);
  free(r);
  free(expanded_keys);
  free(path);
}

void partial_vole_reconstruct_cmo(const uint8_t* iv, const uint8_t* chall,
                                  const uint8_t* const* pdec, const uint8_t* const* com_j,
                                  unsigned int ellhat, unsigned int start, unsigned int len,
                                  verify_vole_mode_ctx_t vole_mode,
                                  const faest_paramset_t* params) {
  unsigned int lambda       = params->faest_param.lambda;
  unsigned int lambda_bytes = lambda / 8;
  unsigned int ellhat_bytes = (ellhat + 7) / 8;
  unsigned int tau0         = params->faest_param.t0;
  unsigned int tau1         = params->faest_param.t1;
  unsigned int k0           = params->faest_param.k0;
  unsigned int k1           = params->faest_param.k1;

  H1_context_t hcom_ctx;
  H1_context_t com_ctx;
  uint8_t* h = NULL;
  if (vole_mode.mode != EXCLUDE_HCOM) {
    H1_init(&hcom_ctx, lambda);
    h = malloc(lambda_bytes * 2);
  }

  unsigned int max_depth = MAX(k0, k1);
  vec_com_rec_t vec_com_rec;
  vec_com_rec.b     = malloc(max_depth * sizeof(uint8_t));
  vec_com_rec.nodes = malloc(max_depth * lambda_bytes);
  memset(vec_com_rec.nodes, 0, max_depth * lambda_bytes);
  vec_com_rec.com_j   = malloc(lambda_bytes * 2);
  uint8_t* tree_nodes = malloc(lambda_bytes * (max_depth - 1) * 2);

  unsigned int end        = start + len;
  // STEP 1: To commit to [start,end] we first compute which trees we need to consider
  unsigned int depth_tau_0     = tau0 * k0;
  unsigned int k0_trees_begin  = (start < depth_tau_0) ? start / k0 : tau0;
  unsigned int k1_trees_begin  = (start < depth_tau_0) ? 0 : (start - depth_tau_0) / k1;
  unsigned int k0_trees_end    = (end < depth_tau_0) ? (end + (k0-1)) / k0 : tau0; // ceiled
  unsigned int k1_trees_end    = (end < depth_tau_0) ? 0 : (end - depth_tau_0 + (k1-1)) / k1;  // ceiled

  unsigned int tree_start = k0_trees_begin+k1_trees_begin;
  unsigned int tree_end   = k0_trees_end+k1_trees_end;

  // Compute the cummulative sum of the tree depths until the requested start
  unsigned int q_progress = k0 * k0_trees_begin + k1 * k1_trees_begin;

  for (unsigned int t = tree_start; t < tree_end; t++) {
    unsigned int tree_depth = t < tau0 ? k0 : k1;

    // q_cache_offset is used to compute the index we should write q to relative to our cache
    unsigned int q_cache_offset  = (q_progress > start) ? q_progress - start : 0; // (i.e. MAX(q_progress-start, 0))
    // [q_begin, q_end] is the q's that t provides (capped by requested start/end)
    unsigned int q_begin         = MAX(q_progress, start); 
    unsigned int q_end           = MIN(end, q_progress+tree_depth);

    uint8_t chalout[MAX_DEPTH];
    ChalDec(chall, t, k0, tau0, k1, tau1, chalout);
    vector_reconstruction(pdec[t], com_j[t], chalout, lambda, tree_depth, tree_nodes, &vec_com_rec);
    unsigned int offset = NumRec(tree_depth, vec_com_rec.b);

    const unsigned int num_seeds = 1 << tree_depth;
    unsigned int q_count = q_end - q_begin;
    uint8_t* sd  = malloc(lambda_bytes);
    uint8_t* com = malloc(lambda_bytes * 2);
    uint8_t* r;

    if (vole_mode.mode != EXCLUDE_HCOM) {
      H1_init(&com_ctx, lambda);
    }
    if (vole_mode.mode != EXCLUDE_Q) {
      r = malloc(ellhat_bytes);
      memset(vole_mode.q+(q_cache_offset*ellhat_bytes), 0, q_count * ellhat_bytes);
    }

    for (unsigned int i = 0; i < num_seeds; i++) {
      unsigned int offset_index = i ^ offset;
      if (offset_index == 0) {
        // As a verifier, we do not have the first seed (i.e. seed i with offset)
        if (vole_mode.mode != EXCLUDE_HCOM) {
          H1_update(&com_ctx, vec_com_rec.com_j, lambda_bytes * 2);
        }
        continue; // Skip the first seed
      }

      extract_sd_com_rec(&vec_com_rec, iv, lambda, i, sd, com);

      if (vole_mode.mode != EXCLUDE_HCOM) {
        H1_update(&com_ctx, com, lambda_bytes * 2);
      }
      if (vole_mode.mode != EXCLUDE_Q) {
        prg(sd, iv, r, lambda, ellhat_bytes);
        for (unsigned int j = q_begin; j < q_end; j++) {
          uint8_t* write_idx = (vole_mode.q+(j-q_begin+q_cache_offset) * ellhat_bytes);
          unsigned int q_v   = j-q_progress;

          // Apply r if i/2^q_v is odd
          if ((offset_index >> q_v) & 1) {
            xor_u8_array(write_idx, r, write_idx, ellhat_bytes);
          }
        }
      }
    }
    if (vole_mode.mode != EXCLUDE_Q) {
      free(r);
    }
    free(sd);
    free(com);
    if (vole_mode.mode != EXCLUDE_HCOM) {
      H1_final(&com_ctx, h, lambda_bytes * 2);
      H1_update(&hcom_ctx, h, lambda_bytes * 2);
    }

    q_progress += tree_depth;
  }
  
  free(vec_com_rec.b);
  free(vec_com_rec.nodes);
  free(vec_com_rec.com_j);
  free(tree_nodes);
  free(h);
  if (vole_mode.mode != EXCLUDE_HCOM) {
    H1_final(&hcom_ctx, vole_mode.hcom, lambda_bytes * 2);
  }
}

void partial_vole_reconstruct_rmo(const uint8_t* iv, const uint8_t* chall,
                                  const uint8_t* const* pdec, const uint8_t* const* com_j,
                                  uint8_t* q, unsigned int ellhat, const faest_paramset_t* params,
                                  unsigned int start, unsigned int len) {
  unsigned int lambda       = params->faest_param.lambda;
  unsigned int lambda_bytes = lambda / 8;
  unsigned int ellhat_bytes = (ellhat + 7) / 8;
  unsigned int tau          = params->faest_param.tau;
  unsigned int tau0         = params->faest_param.t0;
  unsigned int tau1         = params->faest_param.t1;
  unsigned int k0           = params->faest_param.k0;
  unsigned int k1           = params->faest_param.k1;

  unsigned int end = start + len;

  unsigned int max_depth = MAX(k0, k1);
  vec_com_rec_t vec_com_rec;
  vec_com_rec.b       = malloc(max_depth * sizeof(uint8_t));
  vec_com_rec.nodes   = calloc(max_depth, lambda_bytes);
  vec_com_rec.com_j   = malloc(lambda_bytes * 2);
  uint8_t* tree_nodes = malloc(lambda_bytes * (max_depth - 1) * 2);

  uint8_t* sd              = malloc(lambda_bytes);
  uint8_t* com             = malloc(lambda_bytes * 2);
  uint8_t* r               = malloc(ellhat_bytes);

  memset(q, 0, len * lambda_bytes);

  unsigned int col_idx = 0;
  for (unsigned int t = 0; t < tau; t++) {
    unsigned int depth = t < tau0 ? k0 : k1;
    uint8_t chalout[MAX_DEPTH];
    ChalDec(chall, t, k0, tau0, k1, tau1, chalout);
    vector_reconstruction(pdec[t], com_j[t], chalout, lambda, depth, tree_nodes, &vec_com_rec);

    unsigned int byte_offset = (col_idx / 8);
    unsigned int bit_offset  = (col_idx % 8);

    const unsigned int num_instances = 1 << depth;
    for (unsigned int i = 0; i < num_instances; i++) {
      extract_sd_com_rec(&vec_com_rec, iv, lambda, i, sd, com);
      prg(sd, iv, r, lambda, ellhat_bytes);

      for (unsigned int row_idx = start; row_idx < end; row_idx++) {
        unsigned int byte_idx = row_idx / 8;
        unsigned int bit_idx  = row_idx % 8;
        uint8_t bit           = (r[byte_idx] >> (bit_idx)) & 1;
        if (bit == 0) {
          continue;
        }
        unsigned int write_idx = (row_idx-start) * lambda_bytes + byte_offset;
        unsigned int amount    = (bit_offset + depth + 7) / 8;
        // Avoid carry by breaking into two steps
        q[write_idx + 0] ^= i << bit_offset;
        for (unsigned int j = 1; j < amount; j++) {
          q[write_idx + j] ^= i >> (j * 8 - bit_offset);
        }
      }
    }
    
    col_idx += depth;
  }

  free(sd);
  free(com);
  free(r);
  free(vec_com_rec.b);
  free(vec_com_rec.nodes);
  free(vec_com_rec.com_j);
  free(tree_nodes);
}
