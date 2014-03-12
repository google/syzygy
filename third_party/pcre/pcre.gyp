# Copyright 2011 Google Inc. All Rights Reserved.
# Author: siggi@google.com (Sigurdur Asgeirsson)

{
  'variables': {
    'chromium_code': 1,
  },
  'includes': [
    '../../build/common.gypi',
  ],
  'target_defaults': {
    'include_dirs': [
      'files',
    ],
    'defines': [
      'LINK_SIZE=2',
      'PCRE_STATIC',
      'HAVE_CONFIG_H',
      '_CRT_SECURE_NO_WARNINGS',
    ],
  },
  'targets': [
    {
      'target_name': 'dftables_exe',
      'type': 'executable',
      'sources': [
        'files/dftables.c',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': ['/wd4018', '/wd4996'],
        },
      },
    },      
    {
      'target_name': 'make_tables',
      'type': 'none',
      'dependencies': [
        'dftables_exe',
      ],
      'actions': [
        {
          'action_name': 'make_pcre_chartables',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(PRODUCT_DIR)/dftables_exe.exe',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/pcre_chartables.c', 
          ],
          'action': [
            '<(PRODUCT_DIR)/dftables_exe.exe',
            '<(SHARED_INTERMEDIATE_DIR)/pcre_chartables.c', 
          ],
        },
      ],
    },      
    {
      'target_name': 'pcre_lib',
      'type': 'static_library',
      'dependencies': [
        'make_tables',
      ],
      'sources': [
        # C sources
        'files/pcre_compile.c',
        'files/pcre_config.c',
        'files/pcre_dfa_exec.c',
        'files/pcre_exec.c',
        'files/pcre_fullinfo.c',
        'files/pcre_get.c',
        'files/pcre_globals.c',
        'files/pcre_info.c',
        'files/pcre_internal.h',
        'files/pcre_maketables.c',
        'files/pcre_newline.c',
        'files/pcre_ord2utf8.c',
        'files/pcre_refcount.c',
        'files/pcre_scanner.h',
        'files/pcre_study.c',
        'files/pcre_tables.c',
        'files/pcre_try_flipped.c',
        'files/pcre_ucd.c',
        'files/pcre_valid_utf8.c',
        'files/pcre_version.c',
        'files/pcre_xclass.c',
        'files/pcrecpp.h',
        'files/pcrecpp_internal.h',
        'files/pcreposix.c',
        'files/pcreposix.h',
        'files/ucp.h',
        '<(SHARED_INTERMEDIATE_DIR)/pcre_chartables.c', 
        # C plusplus sourcews
        'files/pcrecpp.cc',
        'files/pcre_scanner.cc',
        'files/pcre_stringpiece.cc',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': ['/wd4018', '/wd4996'],
        },
      },
      'all_dependent_settings': {
        'defines': [
          'LINK_SIZE=2',
          'PCRE_STATIC',
        ],
        'include_dirs': [
          'files',
        ],
      },
    },
    {
      'target_name': 'pcrecpp_unittest',
      'type': 'executable',
      'dependencies': [
        'pcre_lib',
      ],
      'sources': [
        'files/pcrecpp_unittest.cc',
      ],
    },
    {
      'target_name': 'pcre_scanner_unittest',
      'type': 'executable',
      'dependencies': [
        'pcre_lib',
      ],
      'sources': [
        'files/pcre_scanner_unittest.cc',
      ],
    },
    {
      'target_name': 'pcre_stringpiece_unittest',
      'type': 'executable',
      'dependencies': [
        'pcre_lib',
      ],
      'sources': [
        'files/pcre_stringpiece_unittest.cc',
      ],
    },
    {
      'target_name': 'pcredemo',
      'type': 'executable',
      'sources': [
        'files/pcredemo.c',
      ],
      'dependencies': [
        'pcre_lib',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': ['/wd4018', '/wd4996'],
        },
      },
    },      
    {
      'target_name': 'pcregrep',
      'type': 'executable',
      'sources': [
        'files/pcregrep.c',
      ],
      'dependencies': [
        'pcre_lib',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': ['/wd4018', '/wd4996'],
        },
      },
    },      
    {
      'target_name': 'pcretest',
      'type': 'executable',
      'sources': [
        'files/pcretest.c',
      ],
      'dependencies': [
        'pcre_lib',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': ['/wd4018', '/wd4996'],
        },
      },
    },      
  ]
}
