/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "VisionOperation"

#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_vision_operations.h"
#include "medialibrary_data_manager.h"
#include "vision_column.h"

using namespace std;
using namespace OHOS::NativeRdb;
using Uri = OHOS::Uri;

namespace OHOS {
namespace Media {
int32_t MediaLibraryVisionOperations::InsertOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int64_t outRowId = -1;
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK || outRowId < 0) {
        MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}

int32_t MediaLibraryVisionOperations::UpdateOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t updateRows = -1;
    int32_t errCode = rdbStore->Update(cmd, updateRows);
    if (errCode != NativeRdb::E_OK || updateRows < 0) {
        MEDIA_ERR_LOG("Update db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(updateRows);
}

int32_t MediaLibraryVisionOperations::DeleteOperation(MediaLibraryCommand &cmd)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t deleteRows = -1;
    int32_t errCode = rdbStore->Delete(cmd, deleteRows);
    if (errCode != NativeRdb::E_OK || deleteRows < 0) {
        MEDIA_ERR_LOG("Delete db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(deleteRows);
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryVisionOperations::QueryOperation(MediaLibraryCommand &cmd,
    const std::vector<std::string> &columns)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return nullptr;
    }
    return rdbStore->Query(cmd, columns);
}

static int32_t UpdateAnalysisTotal(string &fileId)
{
    string uriTotal = MEDIALIBRARY_DATA_URI + "/" + PAH_ANA_TOTAL;
    Uri uri = Uri(uriTotal);
    DataShare::DataSharePredicates predicate;
    string selection = FILE_ID + " = " + fileId + " AND " + SALIENCY + " = 1";
    predicate.SetWhereClause(selection);
    MediaLibraryCommand cmdTotal(uri);
    DataShare::DataShareValuesBucket valueBucket;
    valueBucket.Put(STATUS, 0);
    valueBucket.Put(SALIENCY, 0);
    return MediaLibraryDataManager::GetInstance()->Update(cmdTotal, valueBucket, predicate);
}

static int32_t  DeleteFromSaliencyTable(string &fileId)
{
    string uriSal = MEDIALIBRARY_DATA_URI + "/" + VISION_SALIENCY_TABLE;
    Uri uri = Uri(uriSal);
    DataShare::DataSharePredicates predicate;
    string selection = FILE_ID + " = " + fileId;
    predicate.SetWhereClause(selection);
    MediaLibraryCommand cmdSal(uri);
    return MediaLibraryDataManager::GetInstance()->Delete(cmdSal, predicate);
}

int32_t MediaLibraryVisionOperations::EditCommitOperation(MediaLibraryCommand &cmd)
{
    if (cmd.GetOprnObject() != OperationObject::FILESYSTEM_PHOTO) {
        return E_SUCCESS;
    }
    const ValuesBucket &values = cmd.GetValueBucket();
    ValueObject valueObject;
    string fileId;
    if (values.GetObject(PhotoColumn::MEDIA_ID, valueObject)) {
        valueObject.GetString(fileId);
    } else {
        return E_HAS_DB_ERROR;
    }

    int32_t updateRows = UpdateAnalysisTotal(fileId);
    MEDIA_DEBUG_LOG("Update %{public}d rows at total for edit commit", updateRows);
    if (updateRows > 0) {
        int32_t delRows = DeleteFromSaliencyTable(fileId);
        MEDIA_DEBUG_LOG("delete %{public}d rows from saliency for edit commit", delRows);
    }
    return E_SUCCESS;
}
}
}
