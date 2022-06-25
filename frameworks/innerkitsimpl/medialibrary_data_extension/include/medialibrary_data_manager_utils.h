/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEDIALIBRARY_DATA_ABILITY_UTILS
#define MEDIALIBRARY_DATA_ABILITY_UTILS

#include <string>
#include <sys/stat.h>
#include <unordered_map>

#include "dir_asset.h"
#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "rdb_store.h"
#include "medialibrary_album_operations.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "datashare_abs_result_set.h"
#include "result_set_bridge.h"

namespace OHOS {
namespace Media {
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;
class MediaLibraryDataManagerUtils {
public:
    MediaLibraryDataManagerUtils();
    ~MediaLibraryDataManagerUtils();

    static std::string GetFileName(const std::string &path);
    static std::string GetParentPath(const std::string &path);
    static bool IsNumber(const std::string &str);
    static std::string GetOperationType(const std::string &uri);
    static std::string GetIdFromUri(const std::string &uri);
    static std::string GetFileTitle(const std::string& displayName);
    static std::string GetNetworkIdFromUri(const std::string &uri);
    static int32_t MakeHashDispalyName(const std::string &input, std::string &outRes);
    static std::string GetDisPlayNameFromPath(std::string &path);
    static void SplitKeyValue(const string& keyValue, string &key, string &value);
    static void SplitKeys(const string& query, vector<string>& keys);
    static string ObtionCondition(string &strQueryCondition, const vector<string> &whereArgs);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_DATA_ABILITY_UTILS
