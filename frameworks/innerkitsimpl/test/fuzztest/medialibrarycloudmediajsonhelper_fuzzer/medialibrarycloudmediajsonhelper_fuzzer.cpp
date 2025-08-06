/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "medialibrarycloudmediajsonhelper_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "mdk_record.h"
#include "mdk_record_field.h"
#include "mdk_database.h"
#include "mdk_record_album_data.h"
#include "mdk_record_photos_data.h"
#include "json_helper.h"
#include "cloud_media_album_handler.h"
#include "mdk_record_reader.h"
#undef private
#include "media_log.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t NAME_LEN = 1;
FuzzedDataProvider* provider;

static void JsonHelperTest()
{
    Json::Value doubleData;
    JsonHelper::GetDoubleFromJson(doubleData, "key", 0.0);
    doubleData["key"] = provider->ConsumeFloatingPoint<double>();
    JsonHelper::GetDoubleFromJson(doubleData, "key", 0.0);
    JsonHelper::JsonToString(doubleData);
    std::string jsonString = provider->ConsumeBytesAsString(NAME_LEN);
    JsonHelper::StringToJson(jsonString);
    Json::Value jsonArray(Json::arrayValue);
    jsonArray.append(provider->ConsumeBytesAsString(NAME_LEN));
    JsonHelper::JsonArrayToString(jsonArray, ",");
    std::vector<std::string> vec;
    JsonHelper::JsonToStrVec(jsonArray, vec);
    std::string randomKey = provider->ConsumeBytesAsString(NAME_LEN);
    JsonHelper::HasSpecifiedKey(doubleData, randomKey);
    JsonHelper::HasSpecifiedKey(doubleData, "key");
}

static void JsonPhotosDataTest1()
{
    MDKAsset asset;
    MDKRecordPhotosData PhotoData;
    PhotoData.SetFileContent(asset);
    PhotoData.GetFileContent();
    PhotoData.SetFileEditData(asset);
    PhotoData.GetFileEditData();
    PhotoData.SetMediaType(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetMediaType();
    PhotoData.SetDuration(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetDuration();
    PhotoData.SetPropertiesDuration(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetPropertiesDuration();
    PhotoData.SetHidden(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetHidden();
    PhotoData.SetHiddenTime(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetHiddenTime();
    PhotoData.SetRelativePath(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetRelativePath();
    PhotoData.SetVirtualPath(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetVirtualPath();
    PhotoData.SetDateModified(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetDateModified();
    PhotoData.SetPhotoMetaDateModified(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetPhotoMetaDateModified();
    PhotoData.SetSubType(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetSubType();
    PhotoData.SetBurstCoverLevel(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetBurstCoverLevel();
    PhotoData.SetBurstKey(provider->ConsumeBytesAsString(NAME_LEN));
}

static void JsonPhotosDataTest2()
{
    MDKRecordPhotosData PhotoData;
    PhotoData.GetBurstKey();
    PhotoData.SetDateYear(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetDateYear();
    PhotoData.SetDateMonth(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetDateMonth();
    PhotoData.SetDateDay(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetDateDay();
    PhotoData.SetShootingMode(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetShootingMode();
    PhotoData.SetShootingModeTag(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetShootingModeTag();
    PhotoData.SetDynamicRangeType(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetDynamicRangeType();
    PhotoData.SetFrontCamera(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetFrontCamera();
    PhotoData.SetEditTime(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetEditTime();
    PhotoData.SetOriginalSubType(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetOriginalSubType();
    PhotoData.SetCoverPosition(provider->ConsumeIntegral<int64_t>());
    PhotoData.GetCoverPosition();
    PhotoData.SetIsRectificationCover(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetIsRectificationCover();
    PhotoData.SetSupportedWatermarkType(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetSupportedWatermarkType();
    PhotoData.SetStrongAssociation(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetStrongAssociation();
    PhotoData.SetCloudFileId(provider->ConsumeIntegral<int32_t>());
    PhotoData.GetCloudFileId();
    PhotoData.SetCloudId(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetCloudId();
    PhotoData.SetOriginalAssetCloudId(provider->ConsumeBytesAsString(NAME_LEN));
    PhotoData.GetOriginalAssetCloudId();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr) {
        return 0;
    }
    OHOS::provider = &fdp;
    OHOS::JsonHelperTest();
    OHOS::JsonPhotosDataTest1();
    OHOS::JsonPhotosDataTest2();
    return 0;
}