/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "rdb_store.h"
#include "medialibrary_album_operations.h"

namespace OHOS {
namespace Media {
class MediaLibraryDataAbilityUtils {
public:
    MediaLibraryDataAbilityUtils();
    ~MediaLibraryDataAbilityUtils();

    static std::string GetFileName(const std::string &path);
    static std::string GetParentPath(const std::string &path);
    static int32_t GetParentIdFromDb(const std::string &path, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static bool IsNumber(const std::string &str);
    static int64_t GetAlbumDateModified(const std::string &albumPath);
    static std::string GetOperationType(const std::string &uri);
    static std::string GetIdFromUri(const std::string &uri);
    static std::string GetMediaTypeUri(MediaType mediaType);
    static bool isFileExistInDb(const std::string &relativePath,
                                     const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::string GetPathFromDb(const std::string &id, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static NativeAlbumAsset CreateAlbum(const std::string relativePath,
                                        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static NativeAlbumAsset GetAlbumAsset(const std::string &id, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static std::string GetFileTitle(const std::string& displayName);
    static bool isAlbumExistInDb(const std::string &relativePath,
                                 const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                 int32_t &outRow);
    static NativeAlbumAsset GetLastAlbumExistInDb(const std::string &relativePath,
                                      const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_DATA_ABILITY_UTILS
