/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PictureDataOperationsTest"
#include "picture_data_operations_test.h"
#include <chrono>
#include <thread>
#include <unistd.h>
#include "media_log.h"
#include "medialibrary_errno.h"
#include "picture_data_operations.h"
#include "picture_manager_thread.h"
#include "picture_handle_service.h"
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
static shared_ptr<PictureDataOperations> g_pictureDataOperations = nullptr;
void PictureDataOperationsTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::SetUpTestCase enter");
    g_pictureDataOperations = make_shared<PictureDataOperations>();
    MEDIA_INFO_LOG("PictureDataOperationsTest::SetUpTestCase end");
}
void PictureDataOperationsTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::TearDownTestCase enter");
    g_pictureDataOperations = nullptr;
    MEDIA_INFO_LOG("PictureDataOperationsTest::TearDownTestCase end");
}
void PictureDataOperationsTest::SetUp()
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::SetUp enter");
}
void PictureDataOperationsTest::TearDown()
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::TearDown enter");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_LowQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 1001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_LowQuality_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_002 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_002";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 200;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 1002, expireTime, false, true));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_002 end");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_LowQuality_Test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_003 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_003";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 300;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 1003, expireTime, true, true));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_LowQuality_Test_003 end");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_HighQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_HighQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_004";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 1004, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, HIGH_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_HighQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_HighQuality_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_HighQuality_Test_002 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_005";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 200;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 1005, expireTime, false, true));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, HIGH_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_HighQuality_Test_002 end");
}

HWTEST_F(PictureDataOperationsTest, InsertPictureData_Replace_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_Replace_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_replace_001";
    auto picture1 = make_shared<Picture>();
    time_t expireTime1 = time(nullptr) + 100;
    auto picturePair1 = sptr<PicturePair>(new PicturePair(picture1, imageId, 2001, expireTime1, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair1, LOW_QUALITY_PICTURE);
    auto picture2 = make_shared<Picture>();
    time_t expireTime2 = time(nullptr) + 200;
    auto picturePair2 = sptr<PicturePair>(new PicturePair(picture2, imageId, 2002, expireTime2, false, true));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair2, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertPictureData_Replace_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetDataWithImageId_LowQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetDataWithImageId_LowQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_get_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 3001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isHighQualityPicture = false;
    bool isTakeEffect = false;
    auto retrievedPicture =
        g_pictureDataOperations->GetDataWithImageId(imageId, isHighQualityPicture, isTakeEffect, true);
    ASSERT_NE(retrievedPicture, nullptr);
    ASSERT_FALSE(isHighQualityPicture);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetDataWithImageId_LowQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetDataWithImageId_NotExist_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetDataWithImageId_NotExist_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_not_exist_001";
    bool isHighQualityPicture = false;
    bool isTakeEffect = false;
    auto retrievedPicture =
        g_pictureDataOperations->GetDataWithImageId(imageId, isHighQualityPicture, isTakeEffect, true);
    ASSERT_EQ(retrievedPicture, nullptr);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetDataWithImageId_NotExist_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, DeleteDataWithImageId_LowQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::DeleteDataWithImageId_LowQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_delete_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 4001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExistBefore = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExistBefore);
    g_pictureDataOperations->DeleteDataWithImageId(imageId, LOW_QUALITY_PICTURE);
    bool isExistAfter = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_FALSE(isExistAfter);
    MEDIA_INFO_LOG("PictureDataOperationsTest::DeleteDataWithImageId_LowQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, DeleteDataWithImageId_HighQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::DeleteDataWithImageId_HighQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_delete_002";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 4002, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    bool isExistBefore = g_pictureDataOperations->IsExsitDataForPictureType(imageId, HIGH_QUALITY_PICTURE);
    ASSERT_TRUE(isExistBefore);
    g_pictureDataOperations->DeleteDataWithImageId(imageId, HIGH_QUALITY_PICTURE);
    bool isExistAfter = g_pictureDataOperations->IsExsitDataForPictureType(imageId, HIGH_QUALITY_PICTURE);
    ASSERT_FALSE(isExistAfter);
    MEDIA_INFO_LOG("PictureDataOperationsTest::DeleteDataWithImageId_HighQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, IsExsitDataForPictureType_WithImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::IsExsitDataForPictureType_WithImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_exist_003";
    bool isExistBefore = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_FALSE(isExistBefore);
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 5003, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExistAfter = g_pictureDataOperations->IsExsitDataForPictureType(imageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExistAfter);
    MEDIA_INFO_LOG("PictureDataOperationsTest::IsExsitDataForPictureType_WithImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetPendingTaskSize_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetPendingTaskSize_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_Test_002 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_pending_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 9001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GT(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_Test_002 end");
}

HWTEST_F(PictureDataOperationsTest, GetLowPendingTaskSize_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    int32_t taskSize = g_pictureDataOperations->GetLowPendingTaskSize();
    ASSERT_GE(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetLowPendingTaskSize_Test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_Test_002 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageId = "test_image_low_pending_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 10001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    int32_t taskSize = g_pictureDataOperations->GetLowPendingTaskSize();
    ASSERT_GT(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_Test_002 end");
}

HWTEST_F(PictureDataOperationsTest, InsertMultiplePictures_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertMultiplePictures_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 5; i++) {
        string imageId = "test_image_multi_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 11001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    }
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 5);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertMultiplePictures_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, InsertMultiplePictures_HighQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertMultiplePictures_HighQuality_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 5; i++) {
        string imageId = "testtest_image_multi_high_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 12001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    }
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 5);
    MEDIA_INFO_LOG("PictureDataOperationsTest::InsertMultiplePictures_HighQuality_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, MixedQualityOperations_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::MixedQualityOperations_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageIdLow = "test_mixed_low_001";
    auto pictureLow = make_shared<Picture>();
    time_t expireTimeLow = time(nullptr) + 100;
    auto picturePairLow =
        sptr<PicturePair>(new PicturePair(pictureLow, imageIdLow, 13001, expireTimeLow, true, false));
    g_pictureDataOperations->InsertPictureData(imageIdLow, picturePairLow, LOW_QUALITY_PICTURE);
    string imageIdHigh = "test_mixed_high_001";
    auto pictureHigh = make_shared<Picture>();
    time_t expireTimeHigh = time(nullptr) + 100;
    auto picturePairHigh =
        sptr<PicturePair>(new PicturePair(pictureHigh, imageIdHigh, 13002, expireTimeHigh, true, false));
    g_pictureDataOperations->InsertPictureData(imageIdHigh, picturePairHigh, HIGH_QUALITY_PICTURE);
    bool isExistLow = g_pictureDataOperations->IsExsitDataForPictureType(imageIdLow, LOW_QUALITY_PICTURE);
    bool isExistHigh = g_pictureDataOperations->IsExsitDataForPictureType(imageIdHigh, HIGH_QUALITY_PICTURE);
    ASSERT_TRUE(isExistLow);
    ASSERT_TRUE(isExistHigh);
    MEDIA_INFO_LOG("PictureDataOperationsTest::MixedQualityOperations_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, HighQualityCapacity_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::HighQualityCapacity_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 10; i++) {
        string imageId = "test_capacity_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 17001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    }
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GT(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::HighQualityCapacity_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, ConcurrentOperations_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::ConcurrentOperations_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    auto insertFunc = [this](int index) {
        string imageId = "test_concurrent_" + to_string(index);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageId, 18001 + index, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    };
    thread t1(insertFunc, 1);
    thread t2(insertFunc, 2);
    thread t3(insertFunc, 3);
    t1.join();
    t2.join();
    t3.join();
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 3);
    MEDIA_INFO_LOG("PictureDataOperationsTest::ConcurrentOperations_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_EmptyImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_EmptyImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 19001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_EmptyImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_LongImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_LongImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId(1000, 'a');
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 20001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_LongImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_SpecialCharsImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_SpecialCharsImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_!@#$%^&*()_+-=[]{}|;':\",./<>?";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 21001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_SpecialCharsImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_NegativeFileId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_NegativeFileId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_negative_fileid_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, -1, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_NegativeFileId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_ZeroFileId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_ZeroFileId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_zero_fileid_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 0, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_ZeroFileId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_LargeFileId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_LargeFileId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_large_fileid_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, INT32_MAX, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_LargeFileId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_FutureExpireTime_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_FutureExpireTime_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_future_expire_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 3600;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 24001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_FutureExpireTime_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, Sequence_DeleteAfterInsert_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_DeleteAfterInsert_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_sequence_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 25001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_FALSE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_DeleteAfterInsert_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, Sequence_GetAfterDelete_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_GetAfterDelete_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_sequence_002";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 26001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    bool isHighQualityPicture = false;
    bool isTakeEffect = false;
    auto retrievedPicture =
        g_pictureDataOperations->GetDataWithImageId(imageImageId, isHighQualityPicture, isTakeEffect, true);
    ASSERT_EQ(retrievedPicture, nullptr);
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_GetAfterDelete_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, Sequence_ReplaceAfterDelete_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_ReplaceAfterDelete_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_sequence_003";
    auto picture1 = make_shared<Picture>();
    time_t expireTime1 = time(nullptr) + 100;
    auto picturePair1 = sptr<PicturePair>(new PicturePair(picture1, imageImageId, 27001, expireTime1, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair1, LOW_QUALITY_PICTURE);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    auto picture2 = make_shared<Picture>();
    time_t expireTime2 = time(nullptr) + 100;
    auto picturePair2 = sptr<PicturePair>(new PicturePair(picture2, imageImageId, 27002, expireTime2, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair2, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::Sequence_ReplaceAfterDelete_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, MultipleInsertSameImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::MultipleInsertSameImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_multi_same_001";
    for (int i = 0; i < 3; i++) {
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageImageId, 28001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    }
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::MultipleInsertSameImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, Performance_LargeInsert_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::Performance_LargeInsert_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    auto startTime = chrono::steady_clock::now();
    for (int i = 0; i < 100; i++) {
        string imageImageId = "test_perf_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageImageId, 29001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    }
    auto endTime = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime).count();
    MEDIA_INFO_LOG("PictureDataOperationsTest::Performance_LargeInsert_Test_001 duration: %{public}lld ms", duration);
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 100);
    MEDIA_INFO_LOG("PictureDataOperationsTest::Performance_LargeInsert_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, StressTest_RapidInsertGet_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::StressTest_RapidInsertGet_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 50; i++) {
        string imageImageId = "test_stress_get_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageImageId, 31001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
        bool isHighQualityPicture = false;
        bool isTakeEffect = false;
        auto retrievedPicture =
            g_pictureDataOperations->GetDataWithImageId(imageImageId, isHighQualityPicture, isTakeEffect, true);
        ASSERT_NE(retrievedPicture, nullptr);
    }
    MEDIA_INFO_LOG("PictureDataOperationsTest::StressTest_RapidInsertGet_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, BoundaryTest_MaxCapacity_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::BoundaryTest_MaxCapacity_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 100; i++) {
        string imageImageId = "test_boundary_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageImageId, 32001 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, HIGH_QUALITY_PICTURE);
    }
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GT(taskSize, 0);
    MEDIA_INFO_LOG("PictureDataOperationsTest::BoundaryTest_MaxCapacity_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetWithDifferentCleanFlags_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetWithDifferentCleanFlags_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_clean_flag_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 34001, expireTime, false, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isHighQualityPicture1 = false;
    bool isTakeEffect1 = false;
    auto retrievedPicture1 =
        g_pictureDataOperations->GetDataWithImageId(imageImageId, isHighQualityPicture1, isTakeEffect1, true);
    ASSERT_NE(retrievedPicture1, nullptr);
    bool isHighQualityPicture2 = false;
    bool isTakeEffect2 = false;
    auto retrievedPicture2 =
        g_pictureDataOperations->GetDataWithImageId(imageImageId, isHighQualityPicture2, isTakeEffect2, false);
    ASSERT_NE(retrievedPicture2, nullptr);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetWithDifferentCleanFlags_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, PicturePair_CopyConstructor_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_CopyConstructor_Test_001 enter");
    string imageImageId = "test_pair_copy_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair1 = sptr<PicturePair>(new PicturePair(picture, imageImageId, 35001, expireTime, true, false));
    PicturePair picturePair2(*picturePair1);
    ASSERT_EQ(picturePair2.fileId_, 35001);
    ASSERT_EQ(picturePair2.photoId_, imageImageId);
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_CopyConstructor_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, PicturePair_AssignmentOperator_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_AssignmentOperator_Test_001 enter");
    string imageImageId1 = "test_pair_assign_001";
    auto picture1 = make_shared<Picture>();
    time_t expireTime1 = time(nullptr) + 100;
    auto picturePair1 = sptr<PicturePair>(new PicturePair(picture1, imageImageId1, 36001, expireTime1, true, false));
    string imageImageId2 = "test_pair_assign_002";
    auto picture2 = make_shared<Picture>();
    time_t expireTime2 = time(nullptr) + 100;
    auto picturePair2 = sptr<PicturePair>(new PicturePair(picture2, imageImageId2, 36002, expireTime2, false, true));
    *picturePair1 = *picturePair2;
    ASSERT_EQ(picturePair1->fileId_, 36002);
    ASSERT_EQ(picturePair1->photoId_, imageImageId2);
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_AssignmentOperator_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, PicturePair_SetTakeEffect_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_SetTakeEffect_Test_001 enter");
    string imageImageId = "test_pair_take_effect_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 37001, expireTime, true, false));
    picturePair->SetTakeEffect(true);
    ASSERT_TRUE(picturePair->isTakeEffect_);
    picturePair->SetTakeEffect(false);
    ASSERT_FALSE(picturePair->isTakeEffect_);
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_SetTakeEffect_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, PicturePair_ToString_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_ToString_Test_001 enter");
    string imageImageId = "test_pair_to_string_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 38001, expireTime, true, false));
    string str = picturePair->ToString();
    ASSERT_FALSE(str.empty());
    MEDIA_INFO_LOG("PictureDataOperationsTest::PicturePair_ToString_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, IsEdited_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::IsEdited_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_edited_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 41001, expireTime, true, true));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::IsEdited_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, MemoryManagement_LargeDataSet_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::MemoryManagement_LargeDataSet_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    for (int i = 0; i < 200; i++) {
        string imageImageId = "test_memory_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageImageId, 43000 + i, expireTime, true, false));
        g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    }
    int32_t taskSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GE(taskSize, 200);
    MEDIA_INFO_LOG("PictureDataOperationsTest::MemoryManagement_LargeDataSet_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_UnicodeImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_UnicodeImageId_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_中文_图片_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 44001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_UnicodeImageId_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, EdgeCase_NullptrPicture_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_NullptrPicture_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_nullptr_001";
    auto picture = nullptr;
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 45001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isHighQualityPicture = false;
    bool isTakeEffect = false;
    auto retrievedPicture =
        g_pictureDataOperations->GetDataWithImageId(imageImageId, isHighQualityPicture, isTakeEffect, true);
    ASSERT_EQ(retrievedPicture, nullptr);
    MEDIA_INFO_LOG("PictureDataOperationsTest::EdgeCase_NullptrPicture_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetPendingTaskSize_AfterOperations_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_AfterOperations_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    int32_t initialSize = g_pictureDataOperations->GetPendingTaskSize();
    string imageImageId = "test_pending_size_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 47001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    int32_t afterInsertSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_GT(afterInsertSize, initialSize);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    int32_t afterDeleteSize = g_pictureDataOperations->GetPendingTaskSize();
    ASSERT_LT(afterDeleteSize, afterInsertSize);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetPendingTaskSize_AfterOperations_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, GetLowPendingTaskSize_AfterOperations_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_AfterOperations_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    int32_t initialSize = g_pictureDataOperations->GetLowPendingTaskSize();
    string imageImageId = "test_low_pending_size_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 48001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    int32_t afterInsertSize = g_pictureDataOperations->GetLowPendingTaskSize();
    ASSERT_GT(afterInsertSize, initialSize);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    int32_t afterDeleteSize = g_pictureDataOperations->GetLowPendingTaskSize();
    ASSERT_LT(afterDeleteSize, afterInsertSize);
    MEDIA_INFO_LOG("PictureDataOperationsTest::GetLowPendingTaskSize_AfterOperations_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, HighQualityPictureMap_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::HighQualityPictureMap_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_high_quality_map_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 49001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, HIGH_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, HIGH_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, HIGH_QUALITY_PICTURE);
    bool isExistAfterDelete = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, HIGH_QUALITY_PICTURE);
    ASSERT_FALSE(isExistAfterDelete);
    MEDIA_INFO_LOG("PictureDataOperationsTest::HighQualityPictureMap_Test_001 end");
}

HWTEST_F(PictureDataOperationsTest, LowQualityPictureMap_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureDataOperationsTest::LowQualityPictureMap_Test_001 enter");
    ASSERT_NE(g_pictureDataOperations, nullptr);
    string imageImageId = "test_low_quality_map_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageImageId, 50001, expireTime, true, false));
    g_pictureDataOperations->InsertPictureData(imageImageId, picturePair, LOW_QUALITY_PICTURE);
    bool isExist = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_TRUE(isExist);
    g_pictureDataOperations->DeleteDataWithImageId(imageImageId, LOW_QUALITY_PICTURE);
    bool isExistAfterDelete = g_pictureDataOperations->IsExsitDataForPictureType(imageImageId, LOW_QUALITY_PICTURE);
    ASSERT_FALSE(isExistAfterDelete);
    MEDIA_INFO_LOG("PictureDataOperationsTest::LowQualityPictureMap_Test_001 end");
}
} // namespace Media
} // namespace OHOS