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

#ifndef OHOS_MEDIALIBRARY_RDBSTORE_H
#define OHOS_MEDIALIBRARY_RDBSTORE_H

#include "medialibrary_unistore.h"
#include "timer.h"

namespace OHOS {
namespace Media {
class MediaLibraryRdbStoreObserver;
class MediaLibraryDataCallBack;

class MediaLibraryRdbStore : public MediaLibraryUnistore {
public:
    MediaLibraryRdbStore(const std::shared_ptr<OHOS::AbilityRuntime::Context> &context);
    virtual ~MediaLibraryRdbStore();

    virtual void Init() override;
    virtual void Stop() override;

    virtual int32_t Insert(MediaLibraryCommand &cmd, int64_t &rowId) override;
    virtual int32_t Delete(MediaLibraryCommand &cmd, int32_t &rowId) override;
    virtual int32_t Update(MediaLibraryCommand &cmd, int32_t &rowId) override;
    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(MediaLibraryCommand &cmd,
                                                         const std::vector<std::string> &columns) override;

    bool SyncPullAllTable(const std::string &bundleName) override;
    bool SyncPullAllTableByDeviceId(const std::string &bundleName, std::vector<std::string> &devices) override;
    bool SyncPullTable(const std::string &bundleName, const std::string &tableName, std::vector<std::string> &devices,
                       bool isLast = false) override;
    bool SyncPushTable(const std::string &bundleName, const std::string &tableName, std::vector<std::string> &devices,
                       bool isLast = false) override;
    virtual int32_t ExecuteSql(const std::string &sql) override;
    // temp
    std::shared_ptr<NativeRdb::RdbStore> GetRaw() const { return rdbStore_; }

private:
    bool SubscribeRdbStoreObserver();
    bool UnSubscribeRdbStoreObserver();
    std::string ObtainTableName(MediaLibraryCommand &cmd);

    const std::string DEVICE_BUNDLENAME = "com.ohos.medialibrary.MediaLibraryDataA";
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_{nullptr};
    std::shared_ptr<MediaLibraryRdbStoreObserver> rdbStoreObs_{nullptr};
    std::string bundleName_{DEVICE_BUNDLENAME};
    NativeRdb::RdbStoreConfig config_{""};
};

class MediaLibraryDataCallBack : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;
    bool GetDistributedTables();

private:
    bool isDistributedTables = false;
};

class MediaLibraryRdbStoreObserver : public NativeRdb::RdbStore::RdbStoreObserver {
public:
    explicit MediaLibraryRdbStoreObserver(std::string &bundleName);
    virtual ~MediaLibraryRdbStoreObserver();
    void OnChange(const std::vector<std::string> &devices) override;

private:
    void NotifyDeviceChange();
    static constexpr int NOTIFY_TIME_INTERVAL = 10000;
    std::unique_ptr<OHOS::Utils::Timer> timer_{nullptr};
    uint32_t timerId_{0};
    std::string bundleName_;
    bool isNotifyDeviceChange_;
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIALIBRARY_RDBSTORE_OPERATIONS_H
