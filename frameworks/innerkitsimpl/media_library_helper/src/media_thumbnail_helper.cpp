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
#define MLOG_TAG "Thumbnail"

#include "media_thumbnail_helper.h"
#include "hitrace_meter.h"
#include "distributed_kv_data_manager.h"
#include "image_packer.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"


using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
MediaThumbnailHelper::MediaThumbnailHelper()
{}

bool MediaThumbnailHelper::isThumbnailFromLcd(Size &size)
{
    return !(size.width <= DEFAULT_THUMBNAIL_SIZE.width &&
            size.height <= DEFAULT_THUMBNAIL_SIZE.height);
}

std::unique_ptr<PixelMap> MediaThumbnailHelper::GetThumbnail(std::string key, Size &size, const std::string &uri)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetThumbnail");

    vector<uint8_t> image;
    if (!GetImage(key, image)) {
        if (!uri.substr(0, MEDIALIBRARY_MEDIA_PREFIX.length()).compare(MEDIALIBRARY_MEDIA_PREFIX)) {
            FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
            return nullptr;
        }

        tracer.Start("GetThumbnail SyncKvstore");
        auto syncStatus = SyncKvstore(key, uri);
        tracer.Finish();

        if (syncStatus != DistributedKv::Status::SUCCESS) {
            MEDIA_ERR_LOG("sync KvStore failed! ret %{public}d", syncStatus);
            FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
            return nullptr;
        }
        if (!GetImage(key, image)) {
            MEDIA_ERR_LOG("get image failed again!");
            FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
            return nullptr;
        }
    }

    unique_ptr<PixelMap> pixelMap;
    if (!ResizeImage(image, size, pixelMap)) {
        MEDIA_ERR_LOG("resize image failed!");
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
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
    std::string networkId = MediaFileUtils::GetNetworkIdFromUri(uri);
    if (networkId.empty()) {
        MEDIA_INFO_LOG("MediaThumbnailHelper::DistributedKv::Status::ERROR");
        return DistributedKv::Status::ERROR;
    }
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    std::vector<std::string> deviceIds = { networkId };
    MEDIA_DEBUG_LOG("Distribute StartTrace:Sync");
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "SyncKvstore singleKvStorePtr_->Sync");
    auto status = singleKvStorePtr_->Sync(deviceIds, OHOS::DistributedKv::SyncMode::PULL, dataQuery);
    MEDIA_DEBUG_LOG("Distribute FinishTrace:Sync");
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

    return status;
}

bool MediaThumbnailHelper::ResizeImage(vector<uint8_t> &data, Size &size, unique_ptr<PixelMap> &pixelMap)
{
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "ResizeImage");

    if (data.size() == 0) {
        MEDIA_ERR_LOG("Data is empty");
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return false;
    }

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "ImageSource::CreateImageSource");
    uint32_t errorCode = Media::SUCCESS;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data.data(),
        data.size(), opts, errorCode);
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create image source %{public}d", errorCode);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return false;
    }

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "imageSource->CreatePixelMap");
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = size.width;
    decodeOpts.desiredSize.height = size.height;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    if (errorCode != Media::SUCCESS) {
        MEDIA_ERR_LOG("Failed to create pixelmap %{public}d", errorCode);
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return false;
    }

    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
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

    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "GetImage singleKvStorePtr_->Get");
    auto status = singleKvStorePtr_->Get(key, res);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("Failed to get key [%{public}s]", key.c_str());
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return false;
    }
    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);

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
