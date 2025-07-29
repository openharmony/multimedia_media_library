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

#include "cloud_media_data_client_handler_processor.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "mdk_record.h"
#include "mdk_record_field.h"
#include "mdk_database.h"
#include "cloud_data_convert_to_vo.h"
#undef private
#include "media_log.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t NUM_BYTES = 1;
FuzzedDataProvider* provider;

static void CloudMediaDataClientHandlerProcessorFuzzer()
{
    CloudMediaDataClientHandlerProcessor processor;
    PhotosVo photosVo;
    photosVo.fileId = provider->ConsumeIntegral<int32_t>();
    photosVo.cloudId = provider->ConsumeBytesAsString(NUM_BYTES);
    photosVo.size = provider->ConsumeIntegral<int64_t>();
    photosVo.path = provider->ConsumeBytesAsString(NUM_BYTES);
    photosVo.fileName = provider->ConsumeBytesAsString(NUM_BYTES);
    photosVo.type = provider->ConsumeIntegral<int32_t>();
    photosVo.modifiedTime = provider->ConsumeIntegral<int64_t>();
    photosVo.originalCloudId = provider->ConsumeBytesAsString(NUM_BYTES);

    std::map<std::string, CloudFileDataVo> attachment;
    CloudFileDataVo file;
    file.fileName = provider->ConsumeBytesAsString(NUM_BYTES);
    file.filePath = provider->ConsumeBytesAsString(NUM_BYTES);
    file.size = provider->ConsumeIntegral<int64_t>();
    attachment[file.fileName] = file;
    photosVo.attachment = attachment;

    std::vector<PhotosVo> photosVoList;
    photosVoList.push_back(photosVo);

    processor.GetCloudNewData(photosVoList);
    processor.GetCloudFdirtyData(photosVoList);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr) {
        return 0;
    }
    OHOS::provider = &fdp;
    OHOS::CloudMediaDataClientHandlerProcessorFuzzer();
    return 0;
}