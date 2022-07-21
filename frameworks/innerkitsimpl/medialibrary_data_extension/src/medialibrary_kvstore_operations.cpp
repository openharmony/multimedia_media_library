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
#define MLOG_TAG "KvStoreOperation"

#include "medialibrary_kvstore_operations.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
std::string MediaLibraryKvStoreOperations::GetRingtoneUriKey(int32_t type)
{
    auto key(RINGTONE_DEFAULT_KEY);
    switch (type) {
        case DEFAULT:
            key = RINGTONE_DEFAULT_KEY;
            break;
        case MULTISIM:
            key = RINGTONE_MULTISIM_KEY;
            break;
        default:
            break;
    }

    return key;
}

string MediaLibraryKvStoreOperations::GetKey(const string &uri)
{
    string oprn("");
    size_t found = uri.rfind('/');
    if (found != string::npos) {
        oprn = uri.substr(found + 1);
    }

    return oprn;
}

int32_t MediaLibraryKvStoreOperations::HandleKvStoreInsertOperations(const string &oprn,
    const ValuesBucket &valuesBucket, const shared_ptr<SingleKvStore> &kvStorePtr)
{
    MEDIA_INFO_LOG("MediaLibraryKvStoreOperations::%{private}s", __func__);
    CHECK_AND_RETURN_RET_LOG(kvStorePtr != nullptr, E_FAIL, "kv store not available");

    ValuesBucket values = const_cast<ValuesBucket &>(valuesBucket);
    ValueObject valueObject;

    if (oprn == MEDIA_KVSTOREOPRN_SET_URI) {
        string ringtoneUri = "";
        if (values.GetObject(MEDIA_DATA_DB_RINGTONE_URI, valueObject)) {
            valueObject.GetString(ringtoneUri);
        }

        CHECK_AND_RETURN_RET_LOG(!ringtoneUri.empty(), E_FAIL, "uri is empty");

        int32_t ringtoneType = E_FAIL;
        if (values.GetObject(MEDIA_DATA_DB_RINGTONE_TYPE, valueObject)) {
            valueObject.GetInt(ringtoneType);
        }

        CHECK_AND_RETURN_RET_LOG(ringtoneType >= DEFAULT && ringtoneType <= MULTISIM, E_FAIL, "wrong type");

        auto key = GetRingtoneUriKey(ringtoneType);
        Value value = Value(ringtoneUri);
        if (kvStorePtr->Put(key, value) != Status::SUCCESS) {
            MEDIA_ERR_LOG("ringtone put to kvStore error");
            return E_FAIL;
        }

        return E_SUCCESS;
    } else if (oprn == MEDIA_KVSTOREOPRN_SET_NOTIFICATION_URI) {
        string notificationUri = "";
        if (values.GetObject(MEDIA_DATA_DB_NOTIFICATION_URI, valueObject)) {
            valueObject.GetString(notificationUri);
        }

        CHECK_AND_RETURN_RET_LOG(!notificationUri.empty(), E_FAIL, "notification uri is empty");

        Value value = Value(notificationUri);
        if (kvStorePtr->Put(RINGTONE_NOTIFICATION_KEY, value) != Status::SUCCESS) {
            MEDIA_ERR_LOG("notification put to kvStore error");
            return E_FAIL;
        }

        return E_SUCCESS;
    } else if (oprn == MEDIA_KVSTOREOPRN_SET_ALARM_URI) {
        string alarmUri = "";
        if (values.GetObject(MEDIA_DATA_DB_ALARM_URI, valueObject)) {
            valueObject.GetString(alarmUri);
        }

        CHECK_AND_RETURN_RET_LOG(!alarmUri.empty(), E_FAIL, "notification uri is empty");

        Value value = Value(alarmUri);
        if (kvStorePtr->Put(RINGTONE_ALARM_KEY, value) != Status::SUCCESS) {
            MEDIA_ERR_LOG("alarm put to kvStore error");
            return E_FAIL;
        }

        return E_SUCCESS;
    }

    return E_FAIL;
}

string MediaLibraryKvStoreOperations::HandleKvStoreGetOperations(const string &uri,
    const shared_ptr<SingleKvStore> &kvStorePtr)
{
    MEDIA_INFO_LOG("MediaLibraryKvStoreOperations::%{private}s", __func__);
    CHECK_AND_RETURN_RET_LOG(kvStorePtr != nullptr, "", "kv store not available");

    std::string valueUri("");
    Value value = Value(valueUri);

    if (uri.find(MEDIA_KVSTOREOPRN_GET_URI) != string::npos) {
        string keyString = GetKey(uri);
        string key = GetRingtoneUriKey(stoi(keyString));
        auto status = kvStorePtr->Get(key, value);
        if (status != Status::SUCCESS) {
            MEDIA_ERR_LOG("%{private}s Get key error: %{private}d", __func__, status);
        }
    } else if (uri.find(MEDIA_KVSTOREOPRN_GET_NOTIFICATION_URI) != string::npos) {
        auto status = kvStorePtr->Get(RINGTONE_NOTIFICATION_KEY, value);
        if (status != Status::SUCCESS) {
            MEDIA_ERR_LOG("%{private}s Get notification key error: %{private}d", __func__, status);
        }
    } else if (uri.find(MEDIA_KVSTOREOPRN_GET_ALARM_URI) != string::npos) {
        auto status = kvStorePtr->Get(RINGTONE_ALARM_KEY, value);
        if (status != Status::SUCCESS) {
            MEDIA_ERR_LOG("%{private}s Get alarm key error: %{private}d", __func__, status);
        }
    }

    return value.ToString();
}
} // namespace Media
} // namespace OHOS
