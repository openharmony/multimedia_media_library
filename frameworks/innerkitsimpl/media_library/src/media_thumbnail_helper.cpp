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

#include "media_thumbnail_helper.h"
#include "media_file_utils.h"
#include "media_data_ability_const.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "distributed_kv_data_manager.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "image_packer.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const string THUMBNAIL_APP_ID = "com.ohos.medialibrary.MediaLibraryDataA";
const string THUMBNAIL_STORE_ID = "MediaThumbnailHelperStoreId1";

void MediaThumbnailHelper::InitKvStore()
{
    MEDIA_INFO_LOG("MediaThumbnailHelper::InitMediaThumbnaiKvStore IN");
    DistributedKvDataManager manager;
    Options options = {
        .createIfMissing = true,
        .encrypt = true,
        .persistant = false,
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
    vector<uint8_t> image;
    if (!GetImage(key, image)) {
        if (uri.empty()) {
            MEDIA_ERR_LOG("uri is empty");
            return nullptr;
        }
        auto syncStatus = SyncKvstore(key, uri);
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
    return singleKvStorePtr_->SyncWithCondition(deviceIds, OHOS::DistributedKv::SyncMode::PULL, dataQuery);
}

bool MediaThumbnailHelper::ResizeImage(vector<uint8_t> &data, Size &size, unique_ptr<PixelMap> &pixelMap)
{
    if (data.size() == 0) {
        MEDIA_ERR_LOG("Data is empty");
        return false;
    }

    uint32_t errorCode = Media::SUCCESS;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data.data(),
        data.size(), opts, errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create image source %{public}d", errorCode);
        return false;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = size.width;
    decodeOpts.desiredSize.height = size.height;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create pixelmap %{public}d", errorCode);
        return false;
    }
    MEDIA_INFO_LOG("MediaThumbnailHelper::ResizeImage OUT");
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

    auto status = singleKvStorePtr_->Get(key, res);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("Failed to get key [%{public}s]", key.c_str());
        return false;
    }

    image = vector<uint8_t>(res.Data());
    MEDIA_INFO_LOG("MediaThumbnailHelper::GetImage success!");
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
