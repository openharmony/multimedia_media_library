/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotoStorageOperation"
#include "photo_storage_operation.h"

#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"

namespace OHOS::Media {
std::shared_ptr<NativeRdb::ResultSet> PhotoStorageOperation::FindStorage(std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoStorageOperation::FindStorage");
    bool conn = rdbStore == nullptr;
    CHECK_AND_RETURN_RET_LOG(!conn, nullptr, "rdbStore is null");
    std::string sql = this->SQL_DB_STORAGE_QUERY;
    int64_t cacheSize = this->GetCacheSize();
    MEDIA_INFO_LOG("Media_Storage: cacheSize = %{public}" PRId64 "", cacheSize);
    std::vector<NativeRdb::ValueObject> params = {cacheSize};
    return rdbStore->QuerySql(sql, params);
}

int64_t PhotoStorageOperation::GetCacheSize()
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoStorageOperation::GetCacheSize");
    size_t totalSize = 0;
    MediaFileUtils::StatDirSize(MEDIA_CACHE_DIR, totalSize);
    return static_cast<int64_t>(totalSize);
}
}  // namespace OHOS::Media