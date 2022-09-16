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
#include "media_log.h"
#include "scanner_utils.h"
#include "media_scanner_manager.h"
#include "imedia_scanner_callback.h"
#include "medialibrary_errno.h"

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

    int32_t g_callbackStatus(0);
    int32_t g_filescanstatus(0);
    bool g_isCallbackReceived(false);

    std::string g_callbackName("");
    std::mutex g_mutex;
    std::condition_variable g_condVar;
    string g_prefixPath = "/storage/media/local/files";
    const mode_t CHOWN_RW_UG = 0660;
} // namespace

ApplicationCallback::ApplicationCallback(const std::string &testCaseName) : testCaseName_(testCaseName) {}

int32_t ApplicationCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    HiLog::Info(LABEL, "OnScanFinished invoked");

    g_callbackStatus = status;
    g_callbackName = testCaseName_;
    g_isCallbackReceived = true;
    g_condVar.notify_all();

    return 0;
}

void MediaScannerUnitTest::WaitForCallback()
{
    HiLog::Info(LABEL, "WaitForCallback invoked");
    std::unique_lock<std::mutex> lock(g_mutex);
    g_condVar.wait_until(lock, std::chrono::system_clock::now() + std::chrono::minutes(1),
        []() { return g_isCallbackReceived == true; });
}

bool CreateFile(const string &filePath)
{
    HiLog::Info(LABEL, "Creating new file: %{public}s", filePath.c_str());
    bool errCode = false;

    if (filePath.empty()) {
        return errCode;
    }

    ofstream file(filePath);
    if (!file) {
        MEDIA_ERR_LOG("Output file path could not be created");
        return errCode;
    }

    if (chmod(filePath.c_str(), CHOWN_RW_UG) == 0) {
        errCode = true;
    }

    file.close();

    return errCode;
}

void MediaScannerUnitTest::SetUpTestCase(void)
{
    HiLog::Info(LABEL, "SetUpTestCase invoked");
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "Scanner instance not available");
    }

    int createRes = mkdir("/storage/media/100/local/files/Pictures", S_IRWXU | S_IRWXG | S_IRWXO);
    if (createRes != 0) {
        HiLog::Error(LABEL, "mkdir err %{public}d", errno);
    }
    EXPECT_EQ(createRes, E_SUCCESS);

    createRes = mkdir("/storage/media/100/local/files/Documents", S_IRWXU | S_IRWXG | S_IRWXO);
    if (createRes != 0) {
        HiLog::Error(LABEL, "mkdir err %{public}d", errno);
    }
    EXPECT_EQ(createRes, E_SUCCESS);

    createRes = mkdir("/storage/media/100/local/files/Download", S_IRWXU | S_IRWXG | S_IRWXO);
    if (createRes != 0) {
        HiLog::Error(LABEL, "mkdir err %{public}d", errno);
    }
    EXPECT_EQ(createRes, E_SUCCESS);
}

void MediaScannerUnitTest::TearDownTestCase(void)
{
    HiLog::Info(LABEL, "TearDownTestCase invoked");

    if (remove("/storage/media/100/local/files/Pictures/gtest_Image1.jpg") != 0
        || remove("/storage/media/100/local/files/Pictures/gtest_Image2.png") != 0
        || remove("/storage/media/100/local/files/Pictures/gtest_Image3.jpeg") != 0
        || remove("/storage/media/100/local/files/Documents/gtest_Text1.txt") != 0
        || remove("/storage/media/100/local/files/Download/.HiddenFile") != 0) {
        HiLog::Error(LABEL, "Test files deletion failed");
    }
}

string ConvertPath(string path)
{
    string tmp = "/storage/media/100/";
    path = tmp + path.substr(strlen("/storage/media/"));
    return path;
}

// SetUp:Execute before each test case
void MediaScannerUnitTest::SetUp() {}

void MediaScannerUnitTest::TearDown(void) {}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with media files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_001, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath;
    HiLog::Info(LABEL, "ScanDir test case for: %{public}s", path.c_str());

    int result;
    std::string testcaseName("mediascanner_ScanDir_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanDir(path, appCallback);
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
 * Function : Scan a jpg image file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_001, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/Pictures/gtest_Image1.jpg";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image1.jpg");
    EXPECT_EQ(createRes, true);

    // scan the file
    int result;
    std::string testcaseName("mediascanner_ScanImage_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
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
 * Function : Scan a png image file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_002, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/Pictures/gtest_Image2.png";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image2.png");
    EXPECT_EQ(createRes, true);

    int result;
    std::string testcaseName("mediascanner_ScanImage_Test_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
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
 * Function : Scan an audio file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_003, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/Pictures/gtest_Image3.jpeg";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    bool createRes = CreateFile("/storage/media/100/local/files/Pictures/gtest_Image3.jpeg");
    EXPECT_EQ(createRes, true);

    int result;
    std::string testcaseName("mediascanner_ScanImage_Test_003");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
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
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    MEDIA_DEBUG_LOG("mediascanner_ScanTextFile_Test_001 start");
    string path = g_prefixPath + "/Documents/gtest_Text1.txt";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    bool createRes = CreateFile("/storage/media/100/local/files/Documents/gtest_Text1.txt");
    EXPECT_EQ(createRes, true);

    int result;
    std::string testcaseName("mediascanner_ScanTextFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
    MEDIA_DEBUG_LOG("mediascanner_ScanTextFile_Test_001 end");
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
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/Download/.HiddenFile";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    bool createRes = CreateFile("/storage/media/100/local/files/Download/.HiddenFile");
    EXPECT_EQ(createRes, true);

    int result;
    std::string testcaseName("mediascanner_ScanHiddenFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
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
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath;
    HiLog::Info(LABEL, "ScanDir test case for: %{public}s", path.c_str());

    int result;
    std::string testcaseName("mediascanner_ScanDir_test_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanDir(path, appCallback);
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
 * Function: Scan a directory with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_CononicalPathtest_001, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/../files";
    HiLog::Info(LABEL, "ScanDir test case for: %{public}s", path.c_str());

    int result;
    std::string testcaseName("mediascanner_ScanDir_CononicalPathtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanDir(path, appCallback);
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
 * Function: Scan an image file with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanFile_CononicalPathtest_001, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    string path = g_prefixPath + "/../files/Pictures/gtest_Image1.jpg";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    int result;
    std::string testcaseName("mediascanner_ScanFile_CononicalPathtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
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
 * Function: Scan a text file with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanFile_CononicalPathtest_002, TestSize.Level0)
{
    EXPECT_EQ((MediaScannerManager::GetInstance() != nullptr), true);
    if (MediaScannerManager::GetInstance() == nullptr) {
        HiLog::Error(LABEL, "scanner manager get nullptr instance");
        return;
    }

    MEDIA_DEBUG_LOG("mediascanner_ScanFile_CononicalPathtest_002 start");
    string path = g_prefixPath + "/../files/Documents/gtest_Text1.txt";
    HiLog::Info(LABEL, "ScanFile test case for: %{public}s", path.c_str());

    int result;
    std::string testcaseName("mediascanner_ScanFile_CononicalPathtest_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    path = ConvertPath(path);
    result = MediaScannerManager::GetInstance()->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
    MEDIA_DEBUG_LOG("mediascanner_ScanFile_CononicalPathtest_002 end");
}
} // namespace Media
} // namespace OHOS
