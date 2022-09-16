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

#ifndef MEDIA_SCANNER_DB_H
#define MEDIA_SCANNER_DB_H

#include <list>
#include <string>
#include <unordered_map>
#include <vector>

#include "medialibrary_db_const.h"
#include "medialibrary_type_const.h"
#include "metadata.h"
#include "abs_shared_result_set.h"
#include "rdb_errno.h"
#include "result_set.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"
#include "result_set_bridge.h"
#include "datashare_result_set.h"

namespace OHOS {
namespace Media {
class MediaScannerDb {
public:
    MediaScannerDb();
    MediaScannerDb(MediaScannerDb &other) = delete;
    void operator=(const MediaScannerDb &) = delete;
    ~MediaScannerDb() = default;

    static std::unique_ptr<MediaScannerDb> GetDatabaseInstance();
    bool DeleteMetadata(const std::vector<std::string> &idList);
    void NotifyDatabaseChange(const MediaType mediaType);
    void SetRdbHelper(void);

    std::string InsertMetadata(const Metadata &metadata);
    std::string UpdateMetadata(const Metadata &metadata);
    std::string GetFileDBUriFromPath(const std::string &path);
    std::vector<std::string> BatchInsert(const std::vector<Metadata> &metadataList);

    int32_t UpdateMetadata(const std::vector<Metadata> &metadataList);
    int32_t InsertAlbum(const Metadata &metadata);
    int32_t UpdateAlbum(const Metadata &metadata);
    int32_t ReadAlbums(const std::string &path, std::unordered_map<std::string, Metadata> &albumMap);
    std::unordered_map<int32_t, MediaType> GetIdsFromFilePath(const std::string &path);

    int32_t GetIdFromPath(const std::string &path);
    int32_t GetFileBasicInfo(const std::string &path, std::unique_ptr<Metadata> &ptr);

private:
    std::string GetMediaTypeUri(MediaType mediaType);
    int32_t FillMetadata(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
        std::unique_ptr<Metadata> &ptr);
    void ExtractMetaFromColumn(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
        std::unique_ptr<Metadata> &metadata, const std::string &col);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SCANNER_DB_H
