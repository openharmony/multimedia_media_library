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
#define MLOG_TAG "Thumbnail"

#include "thumbnail_service.h"

#include "display_manager.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_aging_helper.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_helper_factory.h"
#include "thumbnail_uri_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace Media {
std::shared_ptr<ThumbnailService> ThumbnailService::thumbnailServiceInstance_{nullptr};
std::mutex ThumbnailService::instanceLock_;
ThumbnailService::ThumbnailService(void)
{
    rdbStorePtr_ = nullptr;
    kvStorePtr_ = nullptr;
}

shared_ptr<ThumbnailService> ThumbnailService::GetInstance()
{
    if (thumbnailServiceInstance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceLock_);
        if (thumbnailServiceInstance_ != nullptr) {
            return thumbnailServiceInstance_;
        }
        thumbnailServiceInstance_ = shared_ptr<ThumbnailService>(new (std::nothrow)ThumbnailService());
    }

    return thumbnailServiceInstance_;
}

static int32_t GetDefaultWindowSize(int32_t &size)
{
    auto &displayMgr = OHOS::Rosen::DisplayManager::GetInstance();
    auto display = displayMgr.GetDefaultDisplay();
    if (display == nullptr) {
        return E_ERR;
    }
    auto width = display->GetWidth();
    auto height = display->GetHeight();
    MEDIA_INFO_LOG("display window size::w %{public}d, h %{public}d", width, height);
    auto maxSize = max(width, height);
    if (maxSize > FULL_SCREEN_SIZE) {
        size = FULL_SCREEN_SIZE;
    }
    return E_OK;
}

int32_t ThumbnailService::Init(const shared_ptr<RdbStore> &rdbStore,
    const shared_ptr<SingleKvStore> &kvStore,
    const shared_ptr<Context> &context)
{
    rdbStorePtr_ = rdbStore;
    kvStorePtr_ = kvStore;
    context_ = context;

    return GetDefaultWindowSize(windowSize_);
}

void ThumbnailService::ReleaseService()
{
    StopAllWorker();
    rdbStorePtr_ = nullptr;
    kvStorePtr_ = nullptr;
    context_ = nullptr;
    thumbnailServiceInstance_ = nullptr;
}

shared_ptr<DataShare::ResultSetBridge> ThumbnailService::GetThumbnail(const string &uri)
{
    string fileId;
    string networkId;
    string uriString = uri;

    Size size;
    bool success = ThumbnailUriUtils::ParseThumbnailInfo(uriString, fileId, size, networkId);
    if (!success) {
        return nullptr;
    }
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .context = context_,
        .networkId = networkId,
        .row = fileId,
        .uri = uri
    };
    shared_ptr<DataShare::ResultSetBridge> resultSet;
    shared_ptr<IThumbnailHelper> thumbnailHelper = ThumbnailHelperFactory::GetThumbnailHelper(size);
    if (thumbnailHelper == nullptr) {
        MEDIA_ERR_LOG("thumbnailHelper nullptr");
        return nullptr;
    }
    if (ThumbnailHelperFactory::IsThumbnailFromLcd(size)) {
        opts.size = windowSize_;
    }
    int32_t err = thumbnailHelper->GetThumbnailPixelMap(opts, resultSet);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetThumbnailPixelMap failed : %{public}d", err);
        return nullptr;
    }
    return resultSet;
}

int32_t ThumbnailService::CreateThumbnailAsync(const std::string &uri)
{
    string fileId;
    string networkId;
    if (!ThumbnailUriUtils::ParseFileUri(uri, fileId, networkId)) {
        MEDIA_ERR_LOG("ParseThumbnailInfo faild");
        return E_ERR;
    }

    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .row = fileId
    };
    Size size = { DEFAULT_THUMBNAIL_SIZE, DEFAULT_THUMBNAIL_SIZE };
    shared_ptr<IThumbnailHelper> thumbnailHelper = ThumbnailHelperFactory::GetThumbnailHelper(size);
    if (thumbnailHelper == nullptr) {
        MEDIA_ERR_LOG("thumbnailHelper nullptr");
        return E_ERR;
    }
    int32_t err = thumbnailHelper->CreateThumbnail(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateThumbnail failed : %{public}d", err);
        return err;
    }

    size = { DEFAULT_LCD_SIZE, DEFAULT_LCD_SIZE };
    shared_ptr<IThumbnailHelper> lcdHelper = ThumbnailHelperFactory::GetThumbnailHelper(size);
    if (lcdHelper == nullptr) {
        MEDIA_ERR_LOG("lcdHelper nullptr");
        return E_ERR;
    }
    opts.size = windowSize_;
    err = lcdHelper->CreateThumbnail(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateLcd failed : %{public}d", err);
        return err;
    }
    return err;
}

int32_t ThumbnailService::CreateThumbnail(const std::string &uri)
{
    string fileId;
    string networkId;
    Size size;
    bool success = ThumbnailUriUtils::ParseThumbnailInfo(uri, fileId, size, networkId);
    if (!success) {
        MEDIA_ERR_LOG("ParseThumbnailInfo faild");
        return E_ERR;
    }

    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .context = context_,
        .row = fileId
    };
    shared_ptr<IThumbnailHelper> thumbnailHelper = ThumbnailHelperFactory::GetThumbnailHelper(size);
    if (thumbnailHelper == nullptr) {
        MEDIA_ERR_LOG("thumbnailHelper nullptr");
        return E_ERR;
    }
    if (ThumbnailHelperFactory::IsThumbnailFromLcd(size)) {
        opts.size = windowSize_;
    }
    int32_t err = thumbnailHelper->CreateThumbnail(opts, true);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateLcd failed : %{public}d", err);
        return err;
    }
    return err;
}

void ThumbnailService::InterruptBgworker()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        asyncWorker->Interrupt();
    }
}

void ThumbnailService::StopAllWorker()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        asyncWorker->Stop();
    }
}

int32_t ThumbnailService::GenerateThumbnails()
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .table = MEDIALIBRARY_TABLE
    };
    int32_t err = ThumbnailGenerateHelper::CreateLcdBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateLcdBatch failed : %{public}d", err);
    }

    err = ThumbnailGenerateHelper::CreateThumbnailBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateThumbnailBatch failed : %{public}d", err);
    }

    return err;
}

int32_t ThumbnailService::LcdAging()
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .table = MEDIALIBRARY_TABLE,
    };
    int32_t err = ThumbnailAgingHelper::AgingLcdBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("AgingLcdBatch failed : %{public}d", err);
    }

    return E_OK;
}

int32_t ThumbnailService::LcdDistributeAging(const string &udid)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .udid = udid
    };
    int32_t err = ThumbnailAgingHelper::AgingDistributeLcdBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("AgingDistributeLcdBatch failed : %{public}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailService::InvalidateDistributeThumbnail(const string &udid)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .udid = udid
    };
    int32_t err = ThumbnailAgingHelper::InvalidateDistributeBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("InvalidateDistributeBatch failed : %{public}d", err);
    }
    return err;
}

bool ThumbnailService::ParseThumbnailInfo(const string &uriString)
{
    return ThumbnailUriUtils::ParseThumbnailInfo(uriString);
}

void ThumbnailService::InvalidateThumbnail(const std::string &id)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .table = MEDIALIBRARY_TABLE,
        .row = id,
    };
    ThumbnailData thumbnailData;
    thumbnailData.thumbnailKey = "invalid";
    thumbnailData.lcdKey = "invalid";
    ThumbnailUtils::DeleteOriginImage(opts, thumbnailData);
    ThumbnailUtils::CleanThumbnailInfo(opts, true, true);
}
} // namespace Media
} // namespace OHOS
