/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bg_task_processor_test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "values_bucket.h"
#include "rdb_utils.h"

#define private public
#include "wal_check_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
const std::string TEST_WAL_FILE_PATH = "/data/storage/el2/database/rdb/media_library.db-wal";
const std::string WAL_FILE_PATH = "/data/medialibrary/database/rdb/media_library.db-wal";

int32_t InsertAsset(int32_t &fileId)
{
    MEDIA_INFO_LOG("start");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();

    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_IS_TEMP, false);
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    fileId = static_cast<int32_t>(outRowId);
    return ret;
}

int32_t InsertTempAsset(int32_t count)
{
    MEDIA_INFO_LOG("start");
    
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    EXPECT_EQ(ret, E_OK);
    return ret;
}

std::shared_ptr<NativeRdb::ResultSet> Query(int32_t fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return nullptr;
    }

    vector<string> columns = { PhotoColumn::PHOTO_IS_TEMP };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY,
        MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return nullptr;
    }
    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file is_temp");
        return nullptr;
    }
    return resultSet;
}

} // namespace Media
} // namespace OHOS
