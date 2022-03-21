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

#include "medialibrary_device_db.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int64_t MediaLibraryDeviceDb::InsertDeviceInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, DEVICE_OPERATION_ERR, "Invalid RDB store");
    int64_t outRowId(0);
    int32_t insertResult = rdbStore->Insert(outRowId, DEVICE_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(insertResult == E_OK, DEVICE_OPERATION_ERR, "Insert failed");

    return outRowId;
}

int32_t MediaLibraryDeviceDb::DeleteDeviceInfo(const std::string &deviceId,
                                               const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG((rdbStore != nullptr) && (!deviceId.empty()), DEVICE_OPERATION_ERR, "Invalid input");

    int32_t deletedRows(DEVICE_OPERATION_ERR);
    vector<string> whereArgs = { deviceId };

    int32_t deleteResult = rdbStore->Delete(deletedRows, DEVICE_TABLE, DEVICE_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(deleteResult == E_OK, DEVICE_OPERATION_ERR, "Delete failed");

    return (deletedRows > 0) ? DATA_ABILITY_SUCCESS : DATA_ABILITY_FAIL;
}

int32_t MediaLibraryDeviceDb::UpdateDeviceInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore)
{
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, DEVICE_OPERATION_ERR, "Invalid input");

    ValueObject obj;
    std::string deviceId;

    auto contains = values.GetObject(DEVICE_DB_DEVICEID, obj);
    if (contains) {
        obj.GetString(deviceId);
    }

    CHECK_AND_RETURN_RET_LOG(!deviceId.empty(), DEVICE_OPERATION_ERR, "Invalid deviceId = %{public}s",
        deviceId.c_str());

    int32_t updatedRows(0);
    vector<string> whereArgs = { deviceId };

    int32_t updateResult = rdbStore->Update(updatedRows, DEVICE_TABLE, values, DEVICE_DB_COND, whereArgs);
    CHECK_AND_RETURN_RET_LOG(updateResult == E_OK, DEVICE_OPERATION_ERR, "Update failed");

    return (updatedRows > 0) ? DATA_ABILITY_SUCCESS : DATA_ABILITY_FAIL;
}
}  // namespace Media
}  // namespace OHOS