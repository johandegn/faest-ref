table_presets = ['128s', '128f', '192s', '192f', '256s', '256f', 'em_192s', 'em_192f']
tables = []

generator = executable(
  'vole_mult_tables',
  files('vole_mult_tables.cpp') + [parameters_header],
  native: true,
  override_options: ['b_lto=false', 'buildtype=release'],
)

foreach preset : table_presets
  tables += custom_target(
    'generate_tables_@0@'.format(preset),
    command: [
      generator,
      '--preset', preset,
      '--emit-c', join_paths('@OUTDIR@', 'tables_@0@.h'.format(preset)),
    ],
    output: [
      'tables_@0@.h'.format(preset),
    ],
    console: false,
  )
endforeach