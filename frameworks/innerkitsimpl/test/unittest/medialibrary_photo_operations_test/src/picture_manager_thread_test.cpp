/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with License.
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
#define MLOG_TAG "PictureManagerThreadTest"
#include "picture_manager_thread_test.h"
#include <chrono>
#include <thread>
#include <unistd.h>
#include "media_log.h"
#include "medialibrary_errno.h"
#include "surface_buffer.h"
#include "picture_data_operations.h"
#include "picture_manager_thread.h"
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
static PictureManagerThread* g_pictureManagerThread = nullptr;
void PictureManagerThreadTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetUpTestCase enter");
    g_pictureManagerThread = PictureManagerThread::GetInstance();
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetUpTestCase end");
}
void PictureManagerThreadTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::TearDownTestCase enter");
    if (g_pictureManagerThread != nullptr) {
        g_pictureManagerThread->Stop();
    }
    MEDIA_INFO_LOG("PictureManagerThreadTest::TearDownTestCase end");
}
void PictureManagerThreadTest::SetUp()
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetUp enter");
}
void PictureManagerThreadTest::TearDown()
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::TearDown enter");
}

HWTEST_F(PictureManagerThreadTest, GetInstance_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetInstance_Test_001 enter");
    auto instance = PictureManagerThread::GetInstance();
    ASSERT_NE(instance, nullptr);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetInstance_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetInstance_Singleton_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetInstance_Singleton_Test_001 enter");
    auto instance1 = PictureManagerThread::GetInstance();
    auto instance2 = PictureManagerThread::GetInstance();
    ASSERT_EQ(instance1, instance2);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetInstance_Singleton_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetDataWithImageId_NotExist_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetDataWithImageId_NotExist_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    string imageId = "test_thread_get_not_exist_001";
    bool isHighQualityPicture = false;
    bool isTakeEffect = false;
    auto retrievedPicture =
        g_pictureManagerThread->GetDataWithImageId(imageId, isHighQualityPicture, isTakeEffect, true);
    ASSERT_EQ(retrievedPicture, nullptr);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetDataWithImageId_NotExist_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, IsExsitPictureByImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::IsExsitPictureByImageId_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    string imageId = "test_thread_exist_image_001";
    bool isExistBefore = g_pictureManagerThread->IsExsitPictureByImageId(imageId);
    ASSERT_FALSE(isExistBefore);
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 5001, expireTime, true, false));
    g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    this_thread::sleep_for(chrono::milliseconds(100));
    bool isExistAfter = g_pictureManagerThread->IsExsitPictureByImageId(imageId);
    ASSERT_TRUE(isExistAfter);
    MEDIA_INFO_LOG("PictureManagerThreadTest::IsExsitPictureByImageId_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetPendingTaskSize_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetPendingTaskSize_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(taskSize, 0);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetPendingTaskSize_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetPendingTaskSize_AfterInsert_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetPendingTaskSize_AfterInsert_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t initialSize = g_pictureManagerThread->GetPendingTaskSize();
    string imageId = "test_thread_pending_size_001";
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 10001, expireTime, true, false));
    g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t afterInsertSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(afterInsertSize, initialSize);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetPendingTaskSize_AfterInsert_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetLowPendingTaskSize_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetLowPendingTaskSize_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetLowPendingTaskSize();
    ASSERT_GE(taskSize, 0);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetLowPendingTaskSize_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, SetLast200mImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetLast200mImageId_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    string imageId = "testset_last_200m_001";
    g_pictureManagerThread->SetLast200mImageId(imageId);
    string retrievedId = g_pictureManagerThread->GetLast200mImageId();
    ASSERT_EQ(retrievedId, imageId);
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetLast200mImageId_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, GetLast200mImageId_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetLast200mImageId_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    string imageId = "testget_last_200m_001";
    g_pictureManagerThread->SetLast200mImageId(imageId);
    string retrievedId = g_pictureManagerThread->GetLast200mImageId();
    ASSERT_EQ(retrievedId, imageId);
    MEDIA_INFO_LOG("PictureManagerThreadTest::GetLast200mImageId_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, MultipleInsert_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::MultipleInsert_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    for (int i = 0; i < 5; i++) {
        string imageId = "test_thread_multi_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 11001 + i, expireTime, true, false));
        g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    }
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(taskSize, 5);
    MEDIA_INFO_LOG("PictureManagerThreadTest::MultipleInsert_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, ConcurrentOperations_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::ConcurrentOperations_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    auto insertFunc = [this](int index) {
        string imageId = "test_thread_concurrent_" + to_string(index);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100;
        auto picturePair =
            sptr<PicturePair>(new PicturePair(picture, imageId, 12001 + index, expireTime, true, false));
        g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    };
    thread t1(insertFunc, 1);
    thread t2(insertFunc, 2);
    thread t3(insertFunc, 3);
    t1.join();
    t2.join();
    t3.join();
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(taskSize, 3);
    MEDIA_INFO_LOG("PictureManagerThreadTest::ConcurrentOperations_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, IsExsitPictureByImageId_HighQuality_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::IsExsitPictureByImageId_HighQuality_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    string imageId = "test_thread_exist_high_001";
    bool isExistBefore = g_pictureManagerThread->IsExsitPictureByImageId(imageId);
    ASSERT_FALSE(isExistBefore);
    auto picture = make_shared<Picture>();
    time_t expireTime = time(nullptr) + 100;
    auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 14001, expireTime, true, false));
    g_pictureManagerThread->InsertPictureData(imageId, picturePair, HIGH_QUALITY_PICTURE);
    this_thread::sleep_for(chrono::milliseconds(100));
    bool isExistAfter = g_pictureManagerThread->IsExsitPictureByImageId(imageId);
    ASSERT_TRUE(isExistAfter);
    MEDIA_INFO_LOG("PictureManagerThreadTest::IsExsitPictureByImageId_HighQuality_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, Performance_LargeDataSet_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::Performance_LargeDataSet_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    auto startTime = chrono::steady_clock::now();
    for (int i = 0; i < 50; i++) {
        string imageId = "test_thread_perf_" + to_string(i);
        auto picture = make_shared<Picture>();
        time_t expireTime = time(nullptr) + 100 + i;
        auto picturePair = sptr<PicturePair>(new PicturePair(picture, imageId, 18001 + i, expireTime, true, false));
        g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
    }
    auto endTime = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime).count();
    MEDIA_INFO_LOG("PictureManagerThreadTest::Performance_LargeDataSet_Test_001 duration: %{public}lld ms", duration);
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(taskSize, 50);
    MEDIA_INFO_LOG("PictureManagerThreadTest::Performance_LargeDataSet_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, SetGetLast200mImageId_Sequence_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetGetLast200mImageId_Sequence_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    for (int i = 0; i < 5; i++) {
        string imageId = "test_seq_last_" + to_string(i);
        g_pictureManagerThread->SetLast200mImageId(imageId);
        string retrievedId = g_pictureManagerThread->GetLast200mImageId();
        ASSERT_EQ(retrievedId, imageId);
    }
    MEDIA_INFO_LOG("PictureManagerThreadTest::SetGetLast200mImageId_Sequence_Test_001 end");
}

HWTEST_F(PictureManagerThreadTest, ThreadSafety_MultipleThreads_Test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("PictureManagerThreadTest::ThreadSafety_MultipleThreads_Test_001 enter");
    ASSERT_NE(g_pictureManagerThread, nullptr);
    g_pictureManagerThread->Start();
    this_thread::sleep_for(chrono::milliseconds(100));
    const int threadCount = 5;
    const int operationsPerThread = 5;
    vector<thread> threads;
    for (int t = 0; t < threadCount; t++) {
        threads.emplace_back([this, t, operationsPerThread]() {
            for (int i = 0; i < operationsPerThread; i++) {
                string imageId = "test_thread_multi_thread_" + to_string(t) + "_" + to_string(i);
                auto picture = make_shared<Picture>();
                time_t expireTime = time(nullptr) + 100;
                auto picturePair =
                    sptr<PicturePair>(new PicturePair(picture, imageId, 22000 + t * 100 + i, expireTime, true, false));
                g_pictureManagerThread->InsertPictureData(imageId, picturePair, LOW_QUALITY_PICTURE);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    this_thread::sleep_for(chrono::milliseconds(100));
    int32_t taskSize = g_pictureManagerThread->GetPendingTaskSize();
    ASSERT_GE(taskSize, threadCount * operationsPerThread);
    MEDIA_INFO_LOG("PictureManagerThreadTest::ThreadSafety_MultipleThreads_Test_001 end");
}
} // namespace Media
} // namespace OHOS