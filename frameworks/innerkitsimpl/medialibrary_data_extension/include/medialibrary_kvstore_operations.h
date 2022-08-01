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

#ifndef OHOS_MEDIALIBRARY_KVSTORE_OPERATIONS_H
#define OHOS_MEDIALIBRARY_KVSTORE_OPERATIONS_H

#include <string>

#include "distributed_kv_data_manager.h"
#include "medialibrary_db_const.h"
#include "values_bucket.h"
#include "rdb_store.h"

namespace OHOS {
namespace Media {
const std::string RINGTONE_DEFAULT_KEY = "default_ringtone";
const std::string RINGTONE_MULTISIM_KEY = "multisim_ringtone";
const std::string RINGTONE_NOTIFICATION_KEY = "notification_tone";
const std::string RINGTONE_ALARM_KEY = "alarm_tone";

enum RingtoneSimType : int32_t {
    DEFAULT = 0,
    MULTISIM
};

class MediaLibraryKvStoreOperations {
public:
    int32_t HandleKvStoreInsertOperations(const std::string &uri, const NativeRdb::ValuesBucket &valuesBucket,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStorePtr);
    std::string HandleKvStoreGetOperations(const std::string &uri,
        const std::shared_ptr<DistributedKv::SingleKvStore> &kvStorePtr);

private:
    std::string GetRingtoneUriKey(int32_t type);
    std::string GetKey(const std::string &uri);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_KVSTORE_OPERATIONS_H
