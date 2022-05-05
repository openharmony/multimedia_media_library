/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "media_thumbnail_helper.h"
#include "hitrace_meter.h"
#include "distributed_kv_data_manager.h"
#include "image_packer.h"
#include "media_file_utils.h"
#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"


using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
static const string THUMBNAIL_APP_ID = "com.ohos.medialibrary.MediaLibraryDataA";
static const string THUMBNAIL_STORE_ID = "MediaThumbnailHelperStoreId1";

void MediaThumbnailHelper::InitKvStore()
{
    MEDIA_INFO_LOG("MediaThumbnailHelper::InitMediaThumbnaiKvStore IN");
    DistributedKvDataManager manager;
    Options options = {
        .createIfMissing = true,
        .encrypt = true,
        .persistent = true,
        .backup = true,
        .autoSync = true,
        .securityLevel = SecurityLevel::NO_LABEL,
        .syncPolicy = SyncPolicy::HIGH,
        .kvStoreType = KvStoreType::SINGLE_VERSION
    };

    AppId appId = { THUMBNAIL_APP_ID };
    StoreId storeId = { THUMBNAIL_STORE_ID };
#ifdef OLD_KV_API
    manager.GetSingleKvStore(options, appId, storeId, [&](Status status, unique_ptr<SingleKvStore> store) {
        if (status != Status::SUCCESS) {
            MEDIA_ERR_LOG("KvStore get failed! %{public}d", status);
        } else {
            singleKvStorePtr_ = std::move(store);
        }
    });
#else
    Status status = manager.GetSingleKvStore(options, appId, storeId, singleKvStorePtr_);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("KvStore get failed! %{public}d", status);
    }
#endif
    MEDIA_INFO_LOG("MediaThumbnailHelper::InitMediaThumbnaiKvStore OUT");
}

MediaThumbnailHelper::MediaThumbnailHelper()
{
    InitKvStore();
}

bool MediaThumbnailHelper::isThumbnailFromLcd(Size &size)
{
    return !(size.width <= DEFAULT_THUMBNAIL_SIZE.width &&
            size.height <= DEFAULT_THUMBNAIL_SIZE.height);
}

std::unique_ptr<PixelMap> MediaThumbnailHelper::GetThumbnail(std::string key, Size &size, const std::string &uri)
{
    StartTrace(HITRACE_TAG_OHOS, "GetThumbnail");

    vector<uint8_t> image;
    if (!GetImage(key, image)) {
        if (!uri.substr(0, MEDIALIBRARY_MEDIA_PREFIX.length()).compare(MEDIALIBRARY_MEDIA_PREFIX)) {
            return nullptr;
        }

        StartTrace(HITRACE_TAG_OHOS, "GetThumbnail SyncKvstore", -1);
        auto syncStatus = SyncKvstore(key, uri);
        FinishTrace(HITRACE_TAG_OHOS);

        if (syncStatus != DistributedKv::Status::SUCCESS) {
            MEDIA_ERR_LOG("sync KvStore failed! ret %{public}d", syncStatus);
            return nullptr;
        }
        if (!GetImage(key, image)) {
            MEDIA_ERR_LOG("get image failed again!");
            return nullptr;
        }
    }

    unique_ptr<PixelMap> pixelMap;
    if (!ResizeImage(image, size, pixelMap)) {
        MEDIA_ERR_LOG("resize image failed!");
        return nullptr;
    }

    FinishTrace(HITRACE_TAG_OHOS);

    return pixelMap;
}

DistributedKv::Status MediaThumbnailHelper::SyncKvstore(std::string key, const std::string &uri)
{
    if (singleKvStorePtr_ == nullptr) {
        MEDIA_INFO_LOG("MediaThumbnailHelper::DistributedKv::Status::ERROR");
        return DistributedKv::Status::ERROR;
    }
    std::string deviceId = MediaFileUtils::GetNetworkIdFromUri(uri);
    if (deviceId.empty()) {
        MEDIA_INFO_LOG("MediaThumbnailHelper::DistributedKv::Status::ERROR");
        return DistributedKv::Status::ERROR;
    }
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    std::vector<std::string> deviceIds = { deviceId };
    MEDIA_DEBUG_LOG("Distribute StartTrace:SyncWithCondition");
    StartTrace(HITRACE_TAG_OHOS, "SyncKvstore singleKvStorePtr_->SyncWithCondition");
    DistributedKv::Status status = singleKvStorePtr_->SyncWithCondition(deviceIds, OHOS::DistributedKv::SyncMode::PULL,
                                                                        dataQuery);
    MEDIA_DEBUG_LOG("Distribute FinishTrace:SyncWithCondition");
    FinishTrace(HITRACE_TAG_OHOS);

    return status;
}

bool MediaThumbnailHelper::ResizeImage(vector<uint8_t> &data, Size &size, unique_ptr<PixelMap> &pixelMap)
{
    StartTrace(HITRACE_TAG_OHOS, "ResizeImage");

    if (data.size() == 0) {
        MEDIA_ERR_LOG("Data is empty");
        return false;
    }

    StartTrace(HITRACE_TAG_OHOS, "ImageSource::CreateImageSource");
    uint32_t errorCode = Media::SUCCESS;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data.data(),
        data.size(), opts, errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create image source %{public}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    StartTrace(HITRACE_TAG_OHOS, "imageSource->CreatePixelMap");
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = size.width;
    decodeOpts.desiredSize.height = size.height;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create pixelmap %{public}d", errorCode);
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    FinishTrace(HITRACE_TAG_OHOS);
    return true;
}

bool MediaThumbnailHelper::GetImage(string &key, vector<uint8_t> &image)
{
    Value res;
    if (key.empty()) {
        MEDIA_ERR_LOG("GetImage key empty");
        return false;
    }

    if (singleKvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("KvStore is not init");
        return false;
    }

    StartTrace(HITRACE_TAG_OHOS, "GetImage singleKvStorePtr_->Get");
    auto status = singleKvStorePtr_->Get(key, res);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("Failed to get key [%{private}s]", key.c_str());
        return false;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    image = vector<uint8_t>(res.Data());

    return true;
}

bool MediaThumbnailHelper::IsImageExist(string &key)
{
    vector<uint8_t> image;
    bool res = GetImage(key, image);

    MEDIA_INFO_LOG("MediaThumbnailHelper::IsImageExist OUT");
    return res;
}
} // namespace Media
} // namespace OHOS
