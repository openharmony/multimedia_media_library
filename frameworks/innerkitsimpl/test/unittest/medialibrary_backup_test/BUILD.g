# Copyright (C) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import("//build/test.gni")
import("//foundation/multimedia/media_library/media_library.gni")

group("unittest") {
  testonly = true

  deps = [ ":medialibrary_backup_test" ]
}

ohos_unittest("medialibrary_backup_test") {
  module_out_path = "media_library/medialibraryextention"
  include_dirs = [
    "./include",
    "${MEDIALIB_INTERFACES_PATH}/inner_api/media_library_helper/include",
    "${MEDIALIB_INTERFACES_PATH}/kits/js/include",
    "${MEDIALIB_UTILS_PATH}/include",
    "${MEDIALIB_INNERKITS_PATH}/media_library_helper/include",
    "${MEDIALIB_INNERKITS_PATH}/medialibrary_data_extension/include",
    "${MEDIALIB_SERVICES_PATH}/media_backup_extension/include",
  ]

  sources = [
    "${MEDIALIB_SERVICES_PATH}/media_backup_extension/src/backup_database_utils.cpp",
    "${MEDIALIB_SERVICES_PATH}/media_backup_extension/src/base_restore.cpp",
    "${MEDIALIB_SERVICES_PATH}/media_backup_extension/src/update_restore.cpp",
    "./src/external_source.cpp",
    "./src/gallery_source.cpp",
    "./src/medialibrary_backup_test.cpp",
  ]

  deps = [
    "${MEDIALIB_INNERKITS_PATH}/media_library_helper:media_library",
    "${MEDIALIB_INNERKITS_PATH}/medialibrary_data_extension:medialibrary_data_extension",
  ]

  external_deps = [
    "ability_base:want",
    "ability_base:zuri",
    "ability_runtime:ability_context_native",
    "ability_runtime:ability_manager",
    "ability_runtime:abilitykit_native",
    "ability_runtime:app_context",
    "ability_runtime:runtime",
    "c_utils:utils",
    "common_event_service:cesfwk_innerkits",
    "data_share:datashare_provider",
    "hilog:libhilog",
    "kv_store:distributeddata_inner",
    "napi:ace_napi",
    "player_framework:media_client",
    "relational_store:native_rdb",
    "relational_store:rdb_data_share_adapter",
  ]

  resource_config_file =
      "${MEDIALIB_INNERKITS_PATH}/test/unittest/resources/ohos_test.xml"
}
