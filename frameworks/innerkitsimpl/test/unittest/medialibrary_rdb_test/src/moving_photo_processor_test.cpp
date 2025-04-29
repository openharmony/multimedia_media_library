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
#include <cstdint>

#include "medialibrary_object_utils.h"
#include "moving_photo_processor_test.h"
#include "medialibrary_subscriber.h"
#include "moving_photo_processor.h"
#include "medialibrary_subscriber_database_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MoingPhotoProcessorTest::SetUpTestCase(void) {}
void MoingPhotoProcessorTest::TearDownTestCase(void) {}
void MoingPhotoProcessorTest::SetUp(void) {}
void MoingPhotoProcessorTest::TearDown(void) {}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : StartProcessLivePhoto&&StartProcessMovingPhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_StartProcessLivePhoto_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::isProcessing_ = false;
    MovingPhotoProcessor::StartProcessMovingPhoto();
    EXPECT_EQ(MovingPhotoProcessor::isProcessing_, false);
    MovingPhotoProcessor::isProcessing_ = false;
    MovingPhotoProcessor::StartProcessLivePhoto();
    EXPECT_EQ(MovingPhotoProcessor::isProcessing_, false);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : StartProcess
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_StartProcess_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::isProcessing_ = false;
    MovingPhotoProcessor::StartProcess();
    EXPECT_EQ(MovingPhotoProcessor::isProcessing_, false);
    MovingPhotoProcessor::isProcessing_ = true;
    MovingPhotoProcessor::StartProcess();
    EXPECT_NE(MovingPhotoProcessor::isProcessing_, true);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : StopProcess
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_StopProcess_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::isProcessing_ = false;
    MovingPhotoProcessor::StartProcessMovingPhoto();
    EXPECT_EQ(MovingPhotoProcessor::isProcessing_, false);
    MovingPhotoProcessor::isProcessing_ = true;
    MovingPhotoProcessor::StopProcess();
    EXPECT_NE(MovingPhotoProcessor::isProcessing_, true);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : GetUpdatedMovingPhotoData
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_GetUpdatedMovingPhotoData_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::MovingPhotoData currentData;
    currentData.fileId = 10;
    currentData.subtype = 10;
    currentData.effectMode = 10;
    currentData.size = 10;
    currentData.path = "/test/path";
    MovingPhotoProcessor::MovingPhotoData newData;
    int32_t ret = -1;
    ret = MovingPhotoProcessor::GetUpdatedMovingPhotoData(currentData, newData);
    EXPECT_NE(ret, -1);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : CompatMovingPhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_CompatMovingPhoto_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::MovingPhotoData currentData;
    currentData.fileId = 10;
    currentData.subtype = 10;
    currentData.effectMode = 10;
    currentData.size = 10;
    currentData.path = "/test/path";
    MovingPhotoProcessor::MovingPhotoDataList dataList;
    dataList.movingPhotos.push_back(currentData);
    MovingPhotoProcessor::CompatMovingPhoto(dataList);
    EXPECT_NE(MovingPhotoProcessor::isProcessing_, true);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : CompatLivePhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_CompatLivePhoto_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoDataList livePhotoDataList;
    MovingPhotoProcessor::LivePhotoData livePhotoData;
    livePhotoData.isLivePhoto = true;
    livePhotoData.fileId = 10;
    livePhotoData.editTime = 3;
    livePhotoData.mediaType = 3;
    livePhotoData.position = 100;
    livePhotoData.path = "/test/path";
    livePhotoDataList.livePhotos.push_back(livePhotoData);
    MovingPhotoProcessor::isProcessing_ = false;
    MovingPhotoProcessor::CompatLivePhoto(livePhotoDataList);
    EXPECT_NE(MovingPhotoProcessor::isProcessing_, true);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : CompatLivePhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_CompatLivePhoto_Test_002, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoDataList livePhotoDataList;
    MovingPhotoProcessor::LivePhotoData livePhotoData;
    livePhotoData.isLivePhoto = true;
    livePhotoData.fileId = 10;
    livePhotoData.editTime = 3;
    livePhotoData.mediaType = 3;
    livePhotoData.position = 100;
    livePhotoData.path = "/test/path";
    livePhotoDataList.livePhotos.push_back(livePhotoData);
    MovingPhotoProcessor::isProcessing_ = true;
    MovingPhotoProcessor::CompatLivePhoto(livePhotoDataList);
    EXPECT_NE(MovingPhotoProcessor::isProcessing_, false);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : ProcessLocalLivePhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_ProcessLocalLivePhoto_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoData livePhotoData;
    livePhotoData.isLivePhoto = true;
    livePhotoData.fileId = 10;
    livePhotoData.editTime = 3;
    livePhotoData.mediaType = 3;
    livePhotoData.position = 100;
    livePhotoData.path = "/test/path";
    int32_t ret = MovingPhotoProcessor::ProcessLocalLivePhoto(livePhotoData);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : ProcessLocalCloudLivePhoto
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_ProcessLocalCloudLivePhoto_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoData livePhotoData;
    livePhotoData.isLivePhoto = false;
    livePhotoData.fileId = 10;
    livePhotoData.editTime = 3;
    livePhotoData.mediaType = 3;
    livePhotoData.position = 100;
    livePhotoData.path = "/test/path";
    int32_t ret;
    ret = MovingPhotoProcessor::ProcessLocalCloudLivePhoto(livePhotoData);
    EXPECT_NE(livePhotoData.isLivePhoto, true);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : GetUpdatedLivePhotoData
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_GetUpdatedLivePhotoData_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoData oldlivePhotoData;
    oldlivePhotoData.isLivePhoto = false;
    oldlivePhotoData.fileId = 10;
    oldlivePhotoData.editTime = 3;
    oldlivePhotoData.mediaType = 3;
    oldlivePhotoData.position = 100;
    oldlivePhotoData.path = "/test/path";
    MovingPhotoProcessor::LivePhotoData newlivePhotoData;
    newlivePhotoData.isLivePhoto = false;
    newlivePhotoData.fileId = 5;
    newlivePhotoData.editTime = 3;
    newlivePhotoData.mediaType = 3;
    newlivePhotoData.position = 50;
    newlivePhotoData.path = "/test/path2";
    int32_t ret;
    ret = MovingPhotoProcessor::GetUpdatedLivePhotoData(oldlivePhotoData, newlivePhotoData);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature : MoingPhotoProcessorTest
 * Function : UpdateLivePhotoData
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MoingPhotoProcessorTest, MoingPhotoProcessorTest_UpdateLivePhotoData_Test_001, TestSize.Level1)
{
    MovingPhotoProcessor::LivePhotoData livePhotoData;
    livePhotoData.isLivePhoto = false;
    livePhotoData.fileId = 10;
    livePhotoData.editTime = 3;
    livePhotoData.mediaType = 3;
    livePhotoData.position = 100;
    livePhotoData.path = "/test/path";
    MovingPhotoProcessor::UpdateLivePhotoData(livePhotoData);
    EXPECT_EQ(MovingPhotoProcessor::isProcessing_, true);
}
} // namespace Media
} // namespace OHOS