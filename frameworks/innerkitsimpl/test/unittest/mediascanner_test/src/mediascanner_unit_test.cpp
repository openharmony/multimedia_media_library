/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "ApplicationMediaScannerGtest"};
    shared_ptr<IMediaScannerClient> g_msInstance = nullptr;

    int32_t g_callbackStatus(0);
    int32_t g_filescanstatus(0);
    bool g_isCallbackReceived(false);

    std::string g_callbackName("");
    std::mutex g_mutex;
    std::condition_variable g_condVar;
    string g_prefixPath = "/storage/media/local/files";
} // namespace

ApplicationCallback::ApplicationCallback(const std::string &testCaseName) : testCaseName_(testCaseName) {}

void ApplicationCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    HiLog::Info(LABEL, "OnScanFinished invoked");
    g_callbackStatus = status;
    g_callbackName = testCaseName_;
    g_isCallbackReceived = true;
    g_condVar.notify_all();
}

void MediaScannerUnitTest::WaitForCallback()
{
    HiLog::Info(LABEL, "WaitForCallback invoked");
    std::unique_lock<std::mutex> lock(g_mutex);
    g_condVar.wait_until(lock, std::chrono::system_clock::now() + std::chrono::minutes(1),
        []() { return g_isCallbackReceived == true; });
}

void MediaScannerUnitTest::SetUpTestCase(void)
{
    HiLog::Info(LABEL, "SetUpTestCase invoked");
    g_msInstance = MediaScannerHelperFactory::CreateScannerHelper();
    if (g_msInstance == nullptr) {
        HiLog::Error(LABEL, "Scanner instance not available");
    }
}

void MediaScannerUnitTest::TearDownTestCase(void)
{
    HiLog::Info(LABEL, "TearDownTestCase invoked");
    g_msInstance = nullptr;

    if (remove("/storage/media/100/local/files/gtest_scanDir/gtest_Audio1.aac") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/gtest_Image1.jpg") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/gtest_Video1.mp4") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/gtest_Text1.txt") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/.HiddenFile") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/FolderWithNomedia/.nomedia") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/FolderWithNomedia") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/.HiddenFolder/sample_textFile.txt") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir/.HiddenFolder") != 0
        || remove("/storage/media/100/local/files/gtest_scanDir") != 0) {
        HiLog::Error(LABEL, "Test files deletion failed");
    }
}

// SetUp:Execute before each test case
void MediaScannerUnitTest::SetUp() {}

void MediaScannerUnitTest::TearDown(void) {}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with empty content
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir";

    EXPECT_EQ((g_msInstance != nullptr), true);
    int result;
    std::string testcaseName("mediascanner_ScanDir_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a image file with 0 size
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/gtest_Image1.jpg";

    // scan the file
    int result;
    std::string testcaseName("mediascanner_ScanImage_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a video file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanVideo_Test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/gtest_Video1.mp4";

    int result;
    std::string testcaseName("mediascanner_ScanVideo_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a audio file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanAudio_Test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/gtest_Audio1.aac";

    int result;
    std::string testcaseName("mediascanner_ScanAudio_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a normal text file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanTextFile_Test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/gtest_Text1.txt";

    int result;
    std::string testcaseName("mediascanner_ScanTextFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a hidden file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanHiddenFile_Test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/.HiddenFile";

    int result;
    std::string testcaseName("mediascanner_ScanHiddenFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with image, video, audio and other type of files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_002, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir";
    int result;
    std::string testcaseName("mediascanner_ScanDir_test_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with .nomedia file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_Nomedia_test_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/FolderWithNomedia";

    // Scan the hidden folder now
    int result;
    std::string testcaseName("mediascanner_ScanDir_Nomedia_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_CononicalPathtest_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/FolderWithNomedia/..";
    int result;
    std::string testcaseName("mediascanner_ScanDir_CononicalPathtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory which is hidden (starts with a .)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_HiddenDirtest_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir/.HiddenFolder";

    int result;
    std::string testcaseName("mediascanner_ScanDir_HiddenDirtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with various file types (including hidden file), hidden and normal folders
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_RecursiveScan_001, TestSize.Level0)
{
    string path = g_prefixPath + "/gtest_scanDir";
    int result;
    std::string testcaseName("mediascanner_ScanDir_RecursiveScan_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}
} // namespace Media
} // namespace OHOS
