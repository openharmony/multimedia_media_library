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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATASHARE_BRIDGE_H
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATASHARE_BRIDGE_H

#include <condition_variable>
#include <mutex>

#include "kvstore_result_set.h"
#include "result_set_bridge.h"
#include "single_kvstore.h"

namespace OHOS {
namespace Media {
class ThumbnailSemaphore {
public:
    explicit ThumbnailSemaphore(int32_t count);
    virtual ~ThumbnailSemaphore() = default;

    void Signal();
    void Wait();

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int32_t count_;
};

class ThumbnailDataShareBridge : public DataShare::ResultSetBridge {
public:
    virtual ~ThumbnailDataShareBridge() = default;
    int GetRowCount(int32_t &count) override;
    int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    int OnGo(int32_t startRowIndex, int32_t targetRowIndex, DataShare::ResultSetBridge::Writer &writer) override;
    static std::shared_ptr<DataShare::ResultSetBridge> Create(
        const std::shared_ptr<DistributedKv::SingleKvStore> &singleKvStorePtr,
        const std::string &thumbnailkey);

private:
    ThumbnailDataShareBridge() = default;
    ThumbnailDataShareBridge(const std::shared_ptr<DistributedKv::SingleKvStore> &kvStore, const std::string &key);
    int Count(std::shared_ptr<DistributedKv::KvStoreResultSet> &kvResultSet);
    bool FillBlock(int startRowIndex, DataShare::ResultSetBridge::Writer &Writer);

    static constexpr int32_t INVALID_COUNT = -1;
    int32_t resultRowCount_ {INVALID_COUNT};
    std::shared_ptr<DistributedKv::SingleKvStore> singleKvStorePtr_;
    std::string thumbnailKey_;
    static ThumbnailSemaphore sem_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_THUMBNAIL_DATASHARE_BRIDGE_H
