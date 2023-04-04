/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_photo_operations.h"

#include "abs_shared_result_set.h"
#include "file_asset.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdbstore.h"
#include "userfile_manager_types.h"
#include "value_object.h"
using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryPhotoOperations::Create(MediaLibraryCommand &cmd)
{
    switch (cmd.GetApi()) {
        case MediaLibraryApi::API_10:
            return CreateV10(cmd);
        case MediaLibraryApi::API_OLD:
            MEDIA_ERR_LOG("this api is not realized yet");
            return E_FAIL;
        default:
            MEDIA_ERR_LOG("get api failed");
            return E_FAIL;
    }
}

int32_t MediaLibraryPhotoOperations::Delete(MediaLibraryCommand& cmd)
{
    return 0;
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryPhotoOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    return nullptr;
}

int32_t MediaLibraryPhotoOperations::Update(MediaLibraryCommand &cmd)
{
    return 0;
}

int32_t MediaLibraryPhotoOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    return 0;
}

int32_t MediaLibraryPhotoOperations::Close(MediaLibraryCommand &cmd)
{
    return 0;
}

int32_t MediaLibraryPhotoOperations::CreateV10(MediaLibraryCommand& cmd)
{
    string displayName;
    int32_t mediaType = 0;
    FileAsset fileAsset;
    ValueObject valueObject;
    ValuesBucket &values = cmd.GetValueBucket();

    CHECK_AND_RETURN_RET(values.GetObject(PhotoColumn::MEDIA_NAME, valueObject), E_HAS_DB_ERROR);
    valueObject.GetString(displayName);
    fileAsset.SetDisplayName(displayName);

    CHECK_AND_RETURN_RET(values.GetObject(PhotoColumn::MEDIA_TYPE, valueObject), E_HAS_DB_ERROR);
    valueObject.GetInt(mediaType);
    fileAsset.SetMediaType(static_cast<MediaType>(mediaType));

    // Check rootdir and extension
    int32_t errCode = CheckDisplayNameWithType(displayName, mediaType);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to Check Dir and Extension");

    errCode = BeginTransaction();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to start transaction");
        TransactionRollback();
        return errCode;
    }

    errCode = SetAssetPathInCreate(fileAsset);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to Solve FileAsset Path and Name");
        TransactionRollback();
        return errCode;
    }

    int32_t outRow = InsertAssetInDb(cmd, fileAsset);
    if (outRow >= 0) {
        MEDIA_ERR_LOG("insert file in db failed, error = %{public}d", outRow);
        TransactionRollback();
        return errCode;
    }

    errCode = TransactionCommit();
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Failed to commit transaction");
        TransactionRollback();
        return errCode;
    }
    return outRow;
}

} // namespace Media
} // namespace OHOS