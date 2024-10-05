/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibrarymediaphotoassetproxy_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>

#define private public
#include "media_photo_asset_proxy.h"
#undef private

#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "system_ability_definition.h"
#include "userfilemgr_uri.h"

namespace OHOS {
using namespace std;
using namespace DataShare;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
static inline int32_t FuzzInt32(const uint8_t *data)
{
    return static_cast<int32_t>(*data);
}

static inline Media::CameraShotType FuzzCameraShotType(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::CameraShotType_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::CameraShotType_FUZZER_LISTS[*data];
    }
    return Media::CameraShotType::IMAGE;
}

static inline Media::PhotoFormat FuzzPhotoFormat(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::PhotoFormat_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::PhotoFormat_FUZZER_LISTS[*data];
    }
    return Media::PhotoFormat::RGBA;
}

static inline Media::PhotoQuality FuzzPhotoQuality(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::PhotoQuality_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::PhotoQuality_FUZZER_LISTS[*data];
    }
    return Media::PhotoQuality::HIGH;
}

void CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, Media::MEDIALIBRARY_DATA_URI);
    }
}

static shared_ptr<Media::PhotoAssetProxy> Init(const uint8_t *data, size_t size)
{
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = make_shared<Media::PhotoAssetProxy>(sDataShareHelper_,
        FuzzCameraShotType(data, size), FuzzInt32(data), FuzzInt32(data));
    return photoAssetProxy;
}

static void MediaLibraryMediaPhotoAssetProxyTest(const uint8_t *data, size_t size)
{
    if (sDataShareHelper_ == nullptr) {
        CreateDataHelper(FUZZ_STORAGE_MANAGER_MANAGER_ID);
    }
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = Init(data, size);
    if (photoAssetProxy == nullptr) {
        return;
    }
    sptr<Media::PhotoProxyFuzzTest> photoProxyFuzzTest = new(std::nothrow) Media::PhotoProxyFuzzTest();
    if (photoProxyFuzzTest == nullptr) {
        return;
    }
    photoProxyFuzzTest->SetFormat(FuzzPhotoFormat(data, size));
    photoProxyFuzzTest->SetPhotoQuality(FuzzPhotoQuality(data, size));

    photoAssetProxy->AddPhotoProxy((sptr<Media::PhotoProxy>&)photoProxyFuzzTest);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaLibraryMediaPhotoAssetProxyTest(data, size);
    return 0;
}