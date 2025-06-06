/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_helper_test.h"

#include "photo_asset_custom_record.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
/*
 * Feature : MediaLibraryHelperUnitTest
 * Function : Check set get function
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryHelperUnitTest, PhotoCustomRecord_SetGet_Test_001, TestSize.Level1)
{
    PhotoAssetCustomRecord photoAssetCustomRecord;

    const int32_t TEST_FILE_ID = 1;
    photoAssetCustomRecord.SetFileId(TEST_FILE_ID);
    EXPECT_EQ(photoAssetCustomRecord.GetFileId(), TEST_FILE_ID);

    const int32_t TEST_SHARE_COUNT = 1;
    photoAssetCustomRecord.SetShareCount(TEST_SHARE_COUNT);
    EXPECT_EQ(photoAssetCustomRecord.GetShareCount(), TEST_SHARE_COUNT);

    const int32_t TEST_LCD_JUMP_COUNT = 1;
    photoAssetCustomRecord.SetLcdJumpCount(TEST_LCD_JUMP_COUNT);
    EXPECT_EQ(photoAssetCustomRecord.GetLcdJumpCount(), TEST_LCD_JUMP_COUNT);

    const ResultNapiType TEST_RESULT_NAPI_TYPE = ResultNapiType::TYPE_USERFILE_MGR;
    photoAssetCustomRecord.SetResultNapiType(TEST_RESULT_NAPI_TYPE);
    EXPECT_EQ(photoAssetCustomRecord.GetResultNapiType(), TEST_RESULT_NAPI_TYPE);
}
} // namespace Media
} // namespace OHOS