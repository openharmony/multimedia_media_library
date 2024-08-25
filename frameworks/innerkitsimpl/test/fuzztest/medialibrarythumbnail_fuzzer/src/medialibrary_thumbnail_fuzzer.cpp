/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibrary_thumbnail_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>

#include "ability_context_impl.h"
#include "datashare_helper.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_predicates.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_service.h"
#include "thumbnail_uri_utils.h"
#include "thumbnail_source_loading.h"

namespace OHOS {
using namespace std;
using namespace DataShare;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data)
{
    return static_cast<int32_t>(*data);
}

static int Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    return Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl, abilityContextImpl,
        sceneCode);
}


static void ThumhnailTest(const uint8_t* data, size_t size)
{
    if (Init() != 0) {
        MEDIA_ERR_LOG("Init medialibrary fail");
        return;
    }
    Media::ThumbnailService::GetInstance()->GetThumbnailFd(FuzzString(data, size),
        FuzzInt32(data));
    string thumUri = "file://media/Photo/1?operation=thumbnail&width=-1&height=-1";
    Media::ThumbnailService::GetInstance()->GetThumbnailFd(thumUri, FuzzInt32(data));
    Media::ThumbnailService::GetInstance()->LcdAging();
    Media::ThumbnailService::GetInstance()->CreateThumbnailFileScaned(FuzzString(data, size),
        FuzzString(data, size), FuzzInt32(data));
    NativeRdb::RdbPredicates rdbPredicate("Photos");
    Media::ThumbnailService::GetInstance()->CreateAstcBatchOnDemand(rdbPredicate, FuzzInt32(data));
    Media::ThumbnailService::GetInstance()->CancelAstcBatchTask(FuzzInt32(data));
    Media::ThumbnailService::GetInstance()->GenerateThumbnailBackground();
    Media::ThumbnailService::GetInstance()->UpgradeThumbnailBackground(false);
    Media::ThumbnailService::GetInstance()->RestoreThumbnailDualFrame();
    Media::ThumbnailService::GetInstance()->CheckCloudThumbnailDownloadFinish();
    Media::ThumbnailService::GetInstance()->InterruptBgworker();
}

static void ThumbnailHelperTest(const uint8_t* data, size_t size)
{
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return;
    }
    Media::ThumbRdbOpt opts = {
        .store = rdbStore->GetRaw(),
        .table = "Photos",
    };
    Media::ThumbnailGenerateHelper::GetThumbnailPixelMap(opts,
        static_cast<Media::ThumbnailType>(FuzzInt32(data)));
    Media::ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, false);
}

static void ThumbnailSourceTest(const uint8_t* data, size_t size)
{
    Media::GetLocalThumbnailPath(FuzzString(data, size), FuzzString(data, size));
    Media::Size mediaSize = {FuzzInt32(data), FuzzInt32(data)};
    Media::ThumbnailData thumbData;
    Media::ConvertDecodeSize(thumbData, mediaSize, mediaSize);
    Media::DecodeOptions option;
    option.fitDensity = FuzzInt32(data);
    Media::GenDecodeOpts(mediaSize, mediaSize, option);
    uint32_t err = 0;
    Media::LoadImageSource(FuzzString(data, size), err);
    Media::NeedAutoResize(mediaSize);
}

static void ParseFileUriTest(const uint8_t* data, size_t size)
{
    string outFileId;
    string outNetworkId;
    string outTableName;
    string uri = "file://media/Photo/2";
    Media::ThumbnailUriUtils::ParseFileUri(uri, outFileId, outNetworkId, outTableName);
    Media::ThumbnailUriUtils::GetDateAddedFromUri(FuzzString(data, size));
    Media::ThumbnailUriUtils::GetFileUriFromUri(FuzzString(data, size));
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ThumhnailTest(data, size);
    OHOS::ThumbnailHelperTest(data, size);
    OHOS::ThumbnailSourceTest(data, size);
    OHOS::ParseFileUriTest(data, size);
    return 0;
}