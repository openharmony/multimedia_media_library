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

#ifndef OHOS_MEDIALIBRARY_KVSTORE_H
#define OHOS_MEDIALIBRARY_KVSTORE_H

#include "distributed_kv_data_manager.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
const std::string KV_STORE_OWNER_DIR = "/storage/cloud/files/.thumbs/Photo";
const std::string KV_STORE_VISITOR_DIR = "/storage/Share/.thumbs/Photo";

enum class KvStoreRoleType : int32_t {
    OWNER,
    VISITOR,
};

enum class KvStoreValueType : int32_t {
    MONTH_ASTC,
    YEAR_ASTC,
};

class MediaLibraryKvStore {
public:
    EXPORT MediaLibraryKvStore() = default;
    EXPORT ~MediaLibraryKvStore() = default;

    // return 0 means init KvStore success, others mean init kvstore fail
    EXPORT int32_t Init(const KvStoreRoleType &roleType, const KvStoreValueType &valueType, const std::string &baseDir);
    EXPORT int32_t Insert(const std::string &key, const std::vector<uint8_t> &value);
    EXPORT int32_t Delete(const std::string &key);
    EXPORT int32_t Query(const std::string &key, std::vector<uint8_t> &value);
    EXPORT int32_t BatchQuery(std::vector<std::string> &batchKeys, std::vector<std::vector<uint8_t>> &values);
    EXPORT bool Close();
private:
    bool GetKvStoreOption(DistributedKv::Options &options, const KvStoreRoleType &roleType, const std::string &baseDir);

    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
    DistributedKv::DistributedKvDataManager dataManager_;
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_KVSTORE_H