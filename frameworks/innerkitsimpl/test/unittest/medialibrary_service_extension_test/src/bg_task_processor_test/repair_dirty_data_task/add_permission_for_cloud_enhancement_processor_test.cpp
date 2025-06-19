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

#include "values_bucket.h"
#include "rdb_utils.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "media_log.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "photo_file_utils.h"
#include "media_app_uri_permission_column.h"
#include "media_library_extend_manager.h"

#define private public
#include "add_permission_for_cloud_enhancement_processor.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
int32_t InsertAsset(int32_t strongAssociation, int32_t &fileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_STRONG_ASSOCIATION, strongAssociation);

    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_EQ(ret, E_OK);
    fileId = static_cast<int32_t>(outRowId);
    MEDIA_INFO_LOG("InsertAsset fileId: %{public}d, strongAssociation: %{public}d", fileId, strongAssociation);

    int32_t rows = 0;
    NativeRdb::RdbPredicates predicate(PhotoColumn::PHOTOS_TABLE);
    predicate.EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    NativeRdb::ValuesBucket values;
    if (strongAssociation == static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT)) {
        values.PutInt(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, fileId - 1);
        MEDIA_INFO_LOG("update associate_file_id: %{public}d", fileId - 1);
    } else if (strongAssociation ==
        static_cast<int32_t>(StrongAssociationType::NORMAL)) {
        values.PutInt(PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, fileId + 1);
        MEDIA_INFO_LOG("update associate_file_id: %{public}d", fileId + 1);
    }
    ret = rdbStore->Update(rows, values, predicate);
    CHECK_AND_RETURN_RET_LOG((ret == E_OK && rows > 0), E_ERR,
        "Failed to Update Enhancement Asset, ret: %{public}d, updateRows: %{public}d",
        ret, rows);
    return ret;
}

int32_t InsertPermissionAsset(int32_t permissionType, int32_t &fileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();

    NativeRdb::ValuesBucket value;
    value.Put(AppUriPermissionColumn::FILE_ID, fileId);
    value.Put(AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    value.Put(AppUriPermissionColumn::URI_TYPE, 1);
    int64_t dateModified = 1749539819360;
    value.Put(AppUriPermissionColumn::DATE_MODIFIED, dateModified);
    int64_t tokenId = 537490057;
    value.Put(AppUriPermissionColumn::SOURCE_TOKENID, tokenId);
    value.Put(AppUriPermissionColumn::TARGET_TOKENID, tokenId);

    int64_t outRowId = -1;
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }
    int32_t ret = rdbStore->Insert(outRowId,
        AppUriPermissionColumn::APP_URI_PERMISSION_TABLE, value);
    MEDIA_INFO_LOG("InsertPermissionAsset fileId: %{public}d, permissionType: %{public}d",
        fileId, permissionType);
    return ret;
}

int32_t QueryPermission(int32_t fileId, int32_t &permissionType)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return E_ERR;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "get rdb store failed");
    NativeRdb::RdbPredicates queryPredicates(AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    queryPredicates.EqualTo(AppUriPermissionColumn::FILE_ID, fileId);
    vector<string> columns = { AppUriPermissionColumn::PERMISSION_TYPE };
    auto resultSet = MediaLibraryRdbStore::StepQueryWithoutCheck(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_ERR, "cannot get permission from origin photo: %{public}d", fileId);
    permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, resultSet);
    resultSet->Close();
    MEDIA_INFO_LOG("fileId: %{public}d, permissionType: %{public}d", fileId, permissionType);
    return E_OK;
}


HWTEST_F(MediaLibraryBgTaskProcessorTest, AddPermissionForCloudEnhancement_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_001 start");
    int32_t fileId = -1;
    int32_t ret = InsertAsset(static_cast<int32_t>(StrongAssociationType::NORMAL), fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertPermissionAsset(
        static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO), fileId);
    EXPECT_EQ(ret, E_OK);
    ret = InsertAsset(static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT), fileId);
    EXPECT_EQ(ret, E_OK);
    auto processor = AddPermissionForCloudEnhancementProcessor();
    processor.AddPermissionForCloudEnhancement();
    int32_t permissionType = -1;
    ret = QueryPermission(fileId, permissionType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    MEDIA_INFO_LOG("AddPermissionForCloudEnhancement_test_001 end");
}

} // namespace Media
} // namespace OHOS
