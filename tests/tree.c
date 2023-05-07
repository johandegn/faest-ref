#include <assert.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#include "../hash_shake.h"
#include "../tree.h"
#include "../instances.h"
#include "../utils.h"

void printTree(const char* label, tree_t* tree) {
  printf("%s:\n", label);
  for (size_t i = 0; i < tree->numNodes; i++) {
    printf("node[%02lu] (have=%d, exists=%d) ", i, tree->haveNode[i], tree->exists[i]);
    printHex("", tree->nodes[i], tree->dataSize);
  }
}
static int contains(uint16_t* list, size_t len, uint16_t value) {
  for (size_t i = 0; i < len; i++) {
    if (list[i] == value) {
      return 1;
    }
  }
  return 0;
}
int runSeedTest(uint16_t* hideList, size_t hideListSize, size_t numLeaves, uint8_t* rootKey,
   faest_paramset_t* params) {
  int freeHideList = 0;
  int ret          = 1;

  if (numLeaves < hideListSize - 1) {
    printf("%s invalid input (numLeaves = %lu, hideListSize = %lu)\n", __func__, numLeaves,
           hideListSize);
    return 0;
  }

  if (hideList == NULL) {
    hideList     = malloc(hideListSize * sizeof(uint16_t));
    freeHideList = 1;
    uint16_t val;
    for (size_t i = 0; i < hideListSize; i++) {
      do {
        val = ((uint16_t)rand()) % numLeaves;
      } while (contains(hideList, i, val));
      hideList[i] = val;
    }
  }

  // printf("hideList: ");
  // for(size_t i = 0; i < hideListSize; i++) {
  //     printf("%u, ", hideList[i]);
  // }
  // printf("\n");

  // memset(iSeed, 0x07, sizeof(iSeed));
  // memset(salt, 0x09, sizeof(salt));

  // printf("%s: Generating seeds\n", __func__);
  tree_t* tree  = generateSeeds(numLeaves, rootKey, params);
  tree_t* tree2 = createTree(numLeaves, params->faest_param.seedSizeBytes);

#if 0
  printTree("tree", tree);
#endif

  size_t initialOutputSize = (tree->numLeaves) * params->faest_param.seedSizeBytes;
  uint8_t* output          = malloc(initialOutputSize);

  size_t expectedOutputLen = revealSeedsSize(numLeaves, hideList, hideListSize, params);
  if (hideListSize > 0 && expectedOutputLen == 0) {
    printf("Failed to get exepctedOutputLen\n");
    ret = 0;
    goto Exit;
  }
  if (expectedOutputLen % params->faest_param.seedSizeBytes != 0) {
    printf("ExepctedOutputLen is not a multiple of the seed length\n");
    ret = 0;
    goto Exit;
  }

  // printf("%s: Revealing seeds\n", __func__);
  size_t outputLen = revealSeeds(tree, hideList, hideListSize, output, initialOutputSize, params);
  if (outputLen == 0) {
    printf("Failed to revealSeeds, output buffer too small\n");
    ret = 0;
    goto Exit;
  }

  if (outputLen != expectedOutputLen) {
    printf("Expected output lengthd doesn't match output length\n");
    ret = 0;
    goto Exit;
  }

  // printf("%s: numLeaves = %lu, revealed %lu\n", __func__, tree->numLeaves,
  // outputLen/tree->dataSize);

  if (params->faest_param.numOpenRounds * ceil_log2(params->faest_param.t / params->faest_param.numOpenRounds) <
      outputLen / tree->dataSize) {
    printf("%s: Output length is larger than expected\n", __func__);
    ret = 0;
    goto Exit;
  }

  // printf("%s: Reconstructing seeds\n", __func__);
  int res =
      reconstructSeeds(tree2, hideList, hideListSize, output, outputLen, params);
  if (res != 0) {
    printf("%s: Reconstructing seeds FAILED\n", __func__);
    ret = 0;
    goto Exit;
  }

  // printf("seeds in reconstructed tree:\n");
  // printSeeds(tree2->nodes[0], params->seedSizeBytes, 15 );

  // Check that we have the correct seeds, and that they match
  size_t firstLeaf = tree->numNodes - tree->numLeaves;
  for (size_t i = firstLeaf; i < tree->numNodes; i++) {
    if (contains(hideList, hideListSize, i - firstLeaf)) {
      if (tree2->haveNode[i]) {
        printf("%s FAIL: reconstructed tree contains a seed that should have been hidden, node %lu "
               "(leaf node %lu)\n",
               __func__, i, i - firstLeaf);
        printHex("tree->nodes[i] ", tree->nodes[i], params->faest_param.seedSizeBytes);
        printHex("tree2->nodes[i]", tree2->nodes[i], params->faest_param.seedSizeBytes);
        ret = 0;
        goto Exit;
      }
    } else {

      if (!tree2->haveNode[i]) {
        printf("%s FAIL: expected to have seed for node %lu, but don't\n", __func__, i);
        ret = 0;
        goto Exit;
      }
      if (!tree->haveNode[i]) {
        printf("%s FAIL: initial tree is missing node %lu -- not contructed properly?\n", __func__,
               i);
        // printTreeInfo("tree", tree);
        ret = 0;
        goto Exit;
      }

      if (memcmp(tree->nodes[i], tree2->nodes[i], params->faest_param.seedSizeBytes) != 0) {
        printf("%s FAIL: reconstructed tree has an incorrect seed node %lu\n", __func__, i);
        ret = 0;
        goto Exit;
      }
    }
  }

Exit:
  if (freeHideList) {
    free(hideList);
  }
  free(output);
  freeTree(tree);
  freeTree(tree2);

  return ret;
}
void printTreeInfo(const char* label, tree_t* tree) {
  printf("%s:\n", label);
  printf("tree->depth = %lu\n", tree->depth);
  printHex("haveNode", tree->haveNode, tree->numNodes);
  ; // If we have the seed or hash for node i, haveNode[i] is 1
  printf("tree->numNodes = %lu\n", tree->numNodes);
  printf("tree->numLeaves = %lu\n", tree->numLeaves);
}

int runMerkleTest(uint16_t* missingLeaves, size_t missingLeavesSize, size_t numLeaves,
                  faest_paramset_t* params) {
  //    uint8_t iSeed[16];
  uint8_t salt[16];
  //    size_t repIndex = 19;
  int freeMissingLeaves = 0;
  int ret               = 1;
  tree_t* tree2         = NULL;

  if (numLeaves < missingLeavesSize - 1) {
    printf("%s invalid input\n", __func__);
    return 0;
  }

  if (missingLeaves == NULL) {
    missingLeaves     = malloc(missingLeavesSize * sizeof(uint16_t));
    freeMissingLeaves = 1;
    uint16_t val;
    for (size_t i = 0; i < missingLeavesSize; i++) {
      do {
        val = ((uint16_t)rand()) % numLeaves;
      } while (contains((size_t*)missingLeaves, i, val));
      missingLeaves[i] = val;
    }
  }

#if 1
  printf("missingLeaves: ");
  for (size_t i = 0; i < missingLeavesSize; i++) {
    printf("%u, ", missingLeaves[i]);
  }
  printf("\n");
#endif

  // Prover side; all leaves are present

  tree_t* tree = createTree(numLeaves, params->faest_param.digestSizeBytes);

  uint8_t** leafData  = malloc(tree->numLeaves * sizeof(uint8_t*));
  uint8_t* slab       = malloc(tree->numLeaves * tree->dataSize);
  uint8_t* slabToFree = slab;
  for (size_t i = 0; i < tree->numLeaves; i++) {
    leafData[i] = slab;
    slab += tree->dataSize;
    memset(leafData[i], (uint8_t)i + 1, tree->dataSize);
  }

  memset(salt, 0x09, sizeof(salt));

  buildMerkleTree(tree, leafData, salt, params);

#if 0
  printTree("Tree after buildMerkleTree", tree);
#endif

  size_t openDataSize = 0;
  uint8_t* openData   = openMerkleTree(tree, missingLeaves, missingLeavesSize, &openDataSize);
  // root is tree->nodes[0]

  // if(params->numOpenedRounds*ceil_log2(params->numMPCRounds/params->numOpenedRounds) <
  // openDataSize/tree->dataSize) {
  //     printf("%s: Output length is larger than expected\n", __func__);
  //     ret = 0;
  //     goto Exit;
  // }

  // prover sends openData, tree->nodes[0] to verifier

  // Verifier side
  tree2 = createTree(numLeaves, params->faest_param.digestSizeBytes);

  for (size_t i = 0; i < missingLeavesSize; i++) {
    leafData[missingLeaves[i]] = NULL;
  }

  ret = addMerkleNodes(tree2, missingLeaves, missingLeavesSize, openData, openDataSize);
  if (ret != 0) {
    printf("Failed to add nodes to Merkle tree tree2\n");
    ret = 0;
    goto Exit;
  }

#if 0
  printTree("tree2 after addMerkleNodes", tree2);
#endif

  ret = verifyMerkleTree(tree2, leafData, salt, params);
  if (ret != 0) {
    printf("Failed to verify Merkle tree\n");
#if 0
    printTreeInfo("tree", tree);
    printTreeInfo("tree2", tree2);
    printTree("tree", tree);
    printTree("tree2", tree2);
#endif
    ret = 0;
    goto Exit;
  }

  if (memcmp(tree->nodes[0], tree2->nodes[0], tree->dataSize) != 0) {
    printf("Recomputed Merkle tree has different root; verification failed\n");
    ret = 0;
    goto Exit;
  }

#if 0
  printTree("tree", tree);
  printTree("tree2", tree2);
#endif

  ret = 1;
Exit:
  if (freeMissingLeaves) {
    free(missingLeaves);
  }
  free(openData);
  free(slabToFree);
  free(leafData);
  freeTree(tree);
  freeTree(tree2);

  return ret;
}
int main(void) {

  size_t tests         = 0;
  size_t passed        = 0;
  size_t numIterations = 50;

  printf("Running seed tree tests\n");

  /* We can use the uint8 32 root, the 128 and 192 aes turncate the root key appropriately in the
  implementation */
  uint8_t root[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  for (faest_paramid_t p = FAEST_128S; p <= FAEST_256F; p++) {
    faest_paramset_t params = faest_get_paramset(p);

    for (size_t i = 0; i < numIterations; i++) {
      passed += runSeedTest(NULL, params.faest_param.numOpenRounds, params.faest_param.t, root, &params);
      tests++;
    }

    for (size_t i = 0; i < numIterations; i++) {
      passed += runSeedTest(NULL, 3, 8, root, &params);
      tests++;
      passed += runSeedTest(NULL, 3, 7, root, &params);
      tests++;
      passed += runSeedTest(NULL, 3, 6, root, &params);
      tests++;
      passed += runSeedTest(NULL, 4, 5, root, &params);
      tests++;
      passed += runSeedTest(NULL, 2, 5, root, &params);
      tests++;
    }

    uint16_t hideList[3] = {2, 3, 6};
    passed += runSeedTest(hideList, 3, 7, root, &params);
    tests++;
    uint16_t hideList2[2] = {2, 3};
    passed += runSeedTest(hideList2, 2, 6, root, &params);
    tests++;
    uint16_t hideList3[2] = {2, 3};
    passed += runSeedTest(hideList3, 2, 5, root, &params);
    tests++;
    uint16_t hideList5[2] = {2, 3};
    passed += runSeedTest(hideList5, 2, 6, root, &params);
    tests++;
  }

  printf("Running Merkle tree tests\n");
  for (faest_paramid_t p = FAEST_128S; p <= FAEST_128F; p++) {
    faest_paramset_t params = faest_get_paramset(p);
    for (size_t i = 0; i < numIterations; i++) {
      passed += runMerkleTest(NULL, params.faest_param.numOpenRounds, params.faest_param.t, &params);
      tests++;
    }
    for (size_t i = 0; i < numIterations; i++) {
      passed += runMerkleTest(NULL, 3, 8, &params);
      tests++;
      passed += runMerkleTest(NULL, 3, 7, &params);
      tests++;
      passed += runMerkleTest(NULL, 3, 6, &params);
      tests++;
      passed += runMerkleTest(NULL, 4, 5, &params);
      tests++;
      passed += runMerkleTest(NULL, 2, 5, &params);
      tests++;
    }

    uint16_t hideList6[3] = {2, 3, 6};
    passed += runMerkleTest(hideList6, 3, 7, &params);
    tests++;
    uint16_t hideList4[2] = {2, 3};
    passed += runMerkleTest(hideList4, 2, 5, &params);
    tests++;
    uint16_t missingLeaves0[2] = {2, 3};
    passed += runMerkleTest(missingLeaves0, 2, 6, &params);
    tests++;
    uint16_t missingLeaves[4] = {4, 5, 6, 7};
    passed += runMerkleTest(missingLeaves, 4, 8, &params);
    tests++;
    uint16_t missingLeaves2[5] = {2, 3, 4, 8, 11};
    passed += runMerkleTest(missingLeaves2, 5, 13, &params);
    tests++;
  }

  printf("Done, %lu of %lu tests passed\n", passed, tests);

  return 0;
}