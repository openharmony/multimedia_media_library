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

#ifndef FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_
#define FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_

#include "ability_connect_callback_stub.h"
#include "ability_context.h"
#include "datashare_proxy.h"
#include "medialibrary_async_worker.h"
#include "pixel_map.h"
#include "result_set_bridge.h"
#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_utils.h"
#include <map>
#include <shared_mutex>

namespace OHOS {
namespace Media {
class GenerateAsyncTaskData : public AsyncTaskData {
public:
    GenerateAsyncTaskData() = default;
    virtual ~GenerateAsyncTaskData() override = default;
    ThumbRdbOpt opts;
    ThumbnailData thumbnailData;
    std::string thumbnailKey;
};

enum WaitStatus {
    INSERT,
    WAIT_SUCCESS,
    TIMEOUT,
};

using ThumbnailMap = std::map<std::string, std::shared_ptr<SyncStatus>>;
class ThumbnailWait {
public:
    ThumbnailWait(bool release);
    ~ThumbnailWait();

    WaitStatus InsertAndWait(const std::string &id, bool isLcd);
    void CheckAndWait(const std::string &id, bool isLcd);

private:
    void Notify();
    std::string id_;
    bool needRelease_{false};
    static ThumbnailMap thumbnailMap_;
    static std::shared_mutex mutex_;
};

class IThumbnailHelper {
public:
    IThumbnailHelper() = default;
    virtual ~IThumbnailHelper() = default;
    virtual int32_t CreateThumbnail(ThumbRdbOpt &opts, bool isSync = false);
    virtual int32_t GetThumbnailPixelMap(ThumbRdbOpt &opts,
        std::shared_ptr<DataShare::ResultSetBridge> &outResultSet);
    static void DeleteThumbnailKv(ThumbRdbOpt &opts);
    static void CreateLcd(AsyncTaskData *data);
    static void CreateThumbnail(AsyncTaskData *data);
    static void AddAsyncTask(MediaLibraryExecute executor, ThumbRdbOpt &opts, ThumbnailData &data, bool isFront);
protected:
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryThumbnailInfo(
        ThumbRdbOpt &opts, ThumbnailData &outData, int &err);
    static std::unique_ptr<PixelMap> GetPixelMap(const std::vector<uint8_t> &image, Size &size);
    static bool DoCreateLcd(ThumbRdbOpt &opts, ThumbnailData &data, bool force = false);
    static bool DoCreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, bool force = false);
    static bool DoThumbnailSync(ThumbRdbOpt &opts, ThumbnailData &outData);
};

class ThumbnailConnection : public AAFwk::AbilityConnectionStub {
public:
    ThumbnailConnection() = default;
    virtual ~ThumbnailConnection() = default;
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    int32_t GetRemoteDataShareHelper(ThumbRdbOpt &opts, sptr<AAFwk::IAbilityConnection> &callback);

private:
    sptr<DataShare::IDataShare> dataShareProxy_;
    SyncStatus status_;
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_SERVICES_THUMBNAIL_SERVICE_INCLUDE_ITHUMBNAIL_HELPER_H_
