/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef DEVCIES_MEADIA_LIBRARY_INFO_INTERACTION_H
#define DEVCIES_MEADIA_LIBRARY_INFO_INTERACTION_H

#include "distributed_kv_data_manager.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Media {
class DevicesInfoInteract final : public DistributedKv::KvStoreSyncCallback,
                                  public std::enable_shared_from_this<DevicesInfoInteract> {
public:
    DevicesInfoInteract();
    virtual ~DevicesInfoInteract();
    DevicesInfoInteract(const DevicesInfoInteract&) = delete;
    DevicesInfoInteract& operator=(const DevicesInfoInteract&) = delete;
    DevicesInfoInteract(const DevicesInfoInteract&&) = delete;
    DevicesInfoInteract& operator=(const DevicesInfoInteract&&) = delete;

    void Init();
    void PutMLDeviceInfos(const std::string &udid);
    bool GetMLDeviceInfos(const std::string &udid, std::string &version);
    void SyncMLDeviceInfos(const std::string &udid, const std::string &devId);
    void SyncCompleted(const std::map<std::string, DistributedKv::Status> &results) override;
private:
    std::string GenerateKey(const std::string &udid);
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    std::string bundleName_;
};
} // namespace Media
} // namespace OHOS
#endif // DEVCIES_MEADIA_LIBRARY_INFO_INTERACTION_H
