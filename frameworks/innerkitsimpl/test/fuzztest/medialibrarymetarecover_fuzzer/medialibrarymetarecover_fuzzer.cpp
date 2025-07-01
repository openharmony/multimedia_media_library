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

#include "medialibrarymetarecover_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "medialibrary_meta_recovery.h"
#undef private
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_asset_operations.h"

namespace OHOS {
using namespace std;
const int32_t NUM_BYTES = 1;
FuzzedDataProvider *provider = nullptr;

const static std::vector<std::string> COLUMN_VECTOR = {
    Media::MediaColumn::MEDIA_ID,
    Media::MediaColumn::MEDIA_FILE_PATH,
    Media::MediaColumn::MEDIA_SIZE,
    Media::PhotoColumn::PHOTO_LATITUDE,
    "test",
};

static void MediaLibraryMetaRecoverTest()
{
    std::shared_ptr<Media::MediaLibraryMetaRecovery> mediaLibraryMetaRecovery =
        std::make_shared<Media::MediaLibraryMetaRecovery>();
    Media::MediaLibraryMetaRecovery::DeleteMetaDataByPath(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryMetaRecovery::GetInstance().StatisticSave();
    Media::MediaLibraryMetaRecovery::GetInstance().StatisticReset();
    Media::MediaLibraryMetaRecovery::GetInstance().RecoveryStatistic();
    mediaLibraryMetaRecovery->StartAsyncRecovery();
    Media::MediaLibraryMetaRecovery::GetInstance().ResetAllMetaDirty();
    std::set<int32_t> status;
    Media::MediaLibraryMetaRecovery::GetInstance().ReadMetaStatusFromFile(status);
    Media::MediaLibraryMetaRecovery::GetInstance().ReadMetaRecoveryCountFromFile();
    Media::MediaLibraryMetaRecovery::GetInstance().QueryRecoveryPhotosTableColumnInfo();
    Media::MediaLibraryMetaRecovery::GetInstance().GetRecoveryPhotosTableColumnInfo();
    for (auto name : COLUMN_VECTOR) {
        Media::MediaLibraryMetaRecovery::GetInstance().GetDataType(name);
    }
    Media::MediaLibraryMetaRecovery::GetInstance().SetRdbRebuiltStatus(provider->ConsumeIntegral<int32_t>());
    Media::MediaLibraryMetaRecovery::GetInstance().StopCloudSync();
    Media::MediaLibraryMetaRecovery::GetInstance().RestartCloudSync();
    Media::MediaLibraryMetaRecovery::GetInstance().CheckRecoveryState();
    Media::MediaLibraryMetaRecovery::GetInstance().InterruptRecovery();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::MediaLibraryMetaRecoverTest();
    return 0;
}