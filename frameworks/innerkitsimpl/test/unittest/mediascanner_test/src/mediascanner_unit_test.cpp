/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "mediascanner_unit_test.h"

#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "scanner_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
    shared_ptr<MediaScannerManager> mediaScannerManager = nullptr;
} // namespace

void MediaScannerUnitTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();

    mediaScannerManager = MediaScannerManager::GetInstance();
}

void MediaScannerUnitTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaScannerUnitTest::SetUp()
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::InitRootDirs();
}

void MediaScannerUnitTest::TearDown(void) {}

/**
 * @tc.number    : MediaScanner_ScanDir_test_001
 * @tc.name      : scan root dir
 * @tc.desc      : scan root dir with six dirs
 */
HWTEST_F(MediaScannerUnitTest,  MediaScanner_ScanDir_test_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanDir(ROOT_MEDIA_DIR, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanImage_Test_001
 * @tc.name      : scan jpg file
 * @tc.desc      : 1.create jpg file Scanner_Image1.jpg
 *                 2.scan this file
 */
HWTEST_F(MediaScannerUnitTest, MediaScanner_ScanImage_Test_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "Pictures/Scanner_Image1.jpg";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanImage_Test_002
 * @tc.name      : scan png file
 * @tc.desc      : 1.create png file Scanner_Image2.png
 *                 2.scan this file
 */
HWTEST_F(MediaScannerUnitTest, MediaScanner_ScanImage_Test_002, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "Pictures/Scanner_Image2.png";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanImage_Test_003
 * @tc.name      : scan jpeg file
 * @tc.desc      : 1.create jpeg file Scanner_Image3.jpeg
 *                 2.scan this file
 */
HWTEST_F(MediaScannerUnitTest, MediaScanner_ScanImage_Test_003, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "Pictures/Scanner_Image3.jpeg";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanTextFile_Test_001
 * @tc.name      : scan text file
 * @tc.desc      : 1.create text file Scanner_Text1.txt
 *                 2.scan this text file
 */
HWTEST_F(MediaScannerUnitTest, MediaScanner_ScanTextFile_Test_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);

    string path = ROOT_MEDIA_DIR + "Docs/Documents/Scanner_Text1.txt";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanHiddenFile_Test_001
 * @tc.name      : scan hidden file
 * @tc.desc      : 1.create hidden file .HiddenFile
 *                 2.scan this hidden file
 *                 3.expect return error
 */
HWTEST_F(MediaScannerUnitTest, MediaScanner_ScanHiddenFile_Test_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "Docs/Download/.HiddenFile";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_FILE_HIDDEN);
    }
}

/**
 * @tc.number    : MediaScanner_ScanDir_CanonicalPathtest_001
 * @tc.name      : scan dir with uncanonical path
 * @tc.desc      : 1.pass dir's uncanonical path
 */
HWTEST_F(MediaScannerUnitTest,  MediaScanner_ScanDir_CanonicalPathtest_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "../files";
    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanDir(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanFile_CanonicalPathtest_001
 * @tc.name      : scan file with uncanonical path
 * @tc.desc      : 1.create file
 *                 2.pass file's uncanonical path
 */
HWTEST_F(MediaScannerUnitTest,  MediaScanner_ScanFile_CanonicalPathtest_001, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "../files/Pictures/Canonical1.jpg";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}

/**
 * @tc.number    : MediaScanner_ScanFile_CanonicalPathtest_002
 * @tc.name      : scan file with uncanonical path
 * @tc.desc      : 1.create file
 *                 2.pass file's uncanonical path
 */
HWTEST_F(MediaScannerUnitTest,  MediaScanner_ScanFile_CanonicalPathtest_002, TestSize.Level1)
{
    ASSERT_NE(mediaScannerManager, nullptr);
    string path = ROOT_MEDIA_DIR + "../files/Docs/Documents/Canonical2.txt";
    EXPECT_EQ(MediaLibraryUnitTestUtils::CreateFileFS(path), true);

    auto scannerCallback = make_shared<TestScannerCallback>();
    int result = mediaScannerManager->ScanFile(path, scannerCallback);
    EXPECT_EQ(result, E_OK);

    if (result == 0) {
        MediaLibraryUnitTestUtils::WaitForCallback(scannerCallback);
        EXPECT_EQ(scannerCallback->status_, E_OK);
    }
}
} // namespace Media
} // namespace OHOS
