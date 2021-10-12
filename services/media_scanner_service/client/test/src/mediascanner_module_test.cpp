/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "mediascanner_module_test.h"
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
} // namespace

ApplicationCallback::ApplicationCallback(const std::string &testCaseName) : testCaseName_(testCaseName) {}

void ApplicationCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    HiLog::Info(LABEL, "Callback received at test application for %{public}s", testCaseName_.c_str());
    HiLog::Info(LABEL, "status [%{public}d] uri [%{public}s] path  [%{public}s]", status, uri.c_str(), path.c_str());
    g_callbackStatus = status;
    g_callbackName = testCaseName_;
    g_isCallbackReceived = true;
    g_condVar.notify_all();
}

void MediaScannerModuleTest::WaitForCallback()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    g_condVar.wait_until(lock, std::chrono::system_clock::now() + std::chrono::minutes(1),
        []() { return g_isCallbackReceived == true; });
    HiLog::Info(LABEL, "Callback wait over. Returning to main function");
}

void MediaScannerModuleTest::SetUpTestCase(void)
{
    HiLog::Info(LABEL, "Creating and Setting skip list file");
    string filePath = "/data/SkipScanFile.txt";
    ofstream file(filePath);
    if (!file.is_open()) {
        HiLog::Info(LABEL, "Skip scan file path could not be created");
    } else {
        HiLog::Info(LABEL, "Flling the skip list");
        file << "/data/media/images/1" << endl;
        file << "/data/media/escapefilelist/image/escapeimage.png" << endl;
        file << "/data/media/escapefilelist/audio/escapaudio.mp3" << endl;
        file << "/data/media/escapefilelist/video/escapvideo.mp4" << endl;
        file << "/data/media/images/2/dummy" << endl;
        file.close();
    }
    g_msInstance = MediaScannerHelperFactory::CreateScannerHelper();
}

void MediaScannerModuleTest::TearDownTestCase(void)
{
    g_msInstance = nullptr;
}

// SetUp:Execute before each test case
void MediaScannerModuleTest::SetUp() {}

void MediaScannerModuleTest::TearDown(void) {}

/*
 * Feature : MediaScannerModuleTest
 * Function : Scan a jpg file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageJPG_Test_001, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageJPG_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/1.jpg";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
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
 * Feature : MediaScannerModuleTest
 * Function : Scan a png file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanImagePNG_Test_002, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImagePNG_Test_002");

    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/2.jpg";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a BMP file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageBMP_Test_003, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageBMP_Test_003");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/3.bmp";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a GIF file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageGIF_Test_004, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageGIF_Test_004");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/4.gif";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a jpg file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageJPGcaps_Test_005, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageJPGcaps_Test_005");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/5.JPG";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a PNG file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImagePNGCaps_Test_006, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImagePNGCaps_Test_006");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/6.PNG";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a BMP file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageBMPCaps_Test_007, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageBMPCaps_Test_007");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/7.BMP";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a GIF file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanImageGIFCaps_Test_008, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanImageGIFCaps_Test_008");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/images/8.GIF";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a aac file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioacc_Test_009, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioacc_Test_009");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/1.aac";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a flac file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioflac_Test_010, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioflac_Test_010");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/2.flac";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a mp3 file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudiomp3_Test_011, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudiomp3_Test_011");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/3.mp3";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a wav file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudiowav_Test_012, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudiowav_Test_012");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/4.wav";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a ogg file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioogg_Test_013, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioogg_Test_013");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/5.ogg";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a AAC file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioAAC_Test_014, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioAAC_Test_014");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/6.AAC";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a FLAC file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioFLAC_Test_015, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioFLAC_Test_015");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/7.FLAC";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a MP3 file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioMP3_Test_016, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioMP3_Test_016");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/8.MP3";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a WAV file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioWAV_Test_017, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioWAV_Test_017");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/9.WAV";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a OGG file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanAudioOGG_Test_018, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanAudioOGG_Test_018");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/audio/10.OGG";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a 3gp file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideo3gp_Test_019, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideo3gp_Test_019");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/1.3gp";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a mov file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideomov_Test_020, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideomov_Test_020");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/2.mov";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a mpg file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideompg_Test_021, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideompg_Test_021");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/3.mpg";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a mp4 file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideomp4_Test_022, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideomp4_Test_022");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/4.mp4";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a 3GP file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideo3GP_Test_023, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideo3GP_Test_023");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/5.3GP";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a MOV file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideoMOV_Test_024, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideoMOV_Test_024");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/6.MOV";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a MPG file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideoMPG_Test_025, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideoMPG_Test_025");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/7.MPG";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a MP4 file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideoMP4_Test_026, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideoMP4_Test_026");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/8.MP4";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a webm file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideowebm_Test_027, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideowebm_Test_027");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/9.webm";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/* Feature : MediaScannerModuleTest
 * Function : Scan a WEBM file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_ScanVideoWEBM_Test_028, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideoWEBM_Test_028");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/video/10.WEBM";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
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
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanvideowithnomediafilefile_Test_077, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanvideowithnomediafilefile_Test_077");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/nomedia/10.WEBM";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result,  g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanimagewithnomediafilefile_Test_078, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanimagewithnomediafilefile_Test_078");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/nomedia/6.PNG";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanaudiowithnomediafilefile_Test_079, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanaudiowithnomediafilefile_Test_079");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/nomedia/4.wav";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanimagewithescapefilelist_Test_080, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanimagewithescapefilelist_Test_080");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/escapefilelist/image/escapeimage.png";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanaudiowithescapefilelist_Test_081, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanaudiowithescapefilelist_Test_081");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/escapefilelist/audio/escapaudio.mp3";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest, mediascanner_Scanvideowithescapefilelist_Test_082, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanvideowithescapefilelist_Test_082");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    string path = "/data/media/escapefilelist/video/escapvideo.mp4";
    HiLog::Info(LABEL, "Path for scanfile = %{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanFile(path, appCallback);

    EXPECT_NE(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with images
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirImage_test_001, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirImage_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/images";
    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with audio files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirAudio_test_002, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirAudio_test_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/audio";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory having video files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirVideo_test_003, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirVideo_test_003");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/video";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory having Audio,Images,video & Other files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirAllTypes_test_004, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirAllTypes_test_004");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/alltypes";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with canonical path
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirCanonicalpath_test_004, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirCanonicalpath_test_004");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../images";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with .
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirinvalidnamewithdotpath_test_005, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirinvalidnamewithdotpath_test_005");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../.images";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with file containing .nomedia file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirinvalidnamewithnomediafile_test_006, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirinvalidnamewithnomediafile_test_006");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../imagesnomedia";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with file containing only folders
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirwithonlyfolders_test_007, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirwithonlyfolders_test_007");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../onlyfolders";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with file containing hidden folders
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirwithonlyfolders_test_008, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirwithonlyfolders_test_008");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../hiddenfolders";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with reursive multiple folders
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirwithonlyfolders_test_009, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirwithonlyfolders_test_009");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/1level/2level/3level/4level/5level/6level/7level/8level/9level/10level";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with reursive multiple folders and in mid has .nomedia folder in 5level
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirwithrecursiveandnomediaatlevel5_test_010, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirwithrecursiveandnomediaatlevel5_test_010");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/1level/2level/3level/4level/5level/6level/7level/8level/9level/10level";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with reursive multiple folders and in mid has .folder in 6level
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanDirwithrecursiveanddotmediaatlevel6_test_011, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanDirwithrecursiveanddotmediaatlevel6_test_011");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/data/media/1level/2level/3level/4level/5level/6level/7level/8level/9level/10level";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with reursive multiple folders and and canonical path in mid has .folder in 6level
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  ScanDirwithrecursiveCanonicalanddotmediaatlevel6_test_012, TestSize.Level1)
{
    int result;
    std::string testcaseName("ScanDirwithrecursiveCanonicalanddotmediaatlevel6_test_012");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../../../../../../../../../../10level";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a dir with recursive multiple folders with canonical path and in mid has .nomedia folder in 5level
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  ScanDirwithrecursiveCanonicalandnomediaatlevel5_test_012, TestSize.Level1)
{
    int result;
    std::string testcaseName("ScanDirwithrecursiveCanonicalandnomediaatlevel5_test_012");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../../../../../../../../../../10level";

    HiLog::Info(LABEL, "Directory to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}
/*
 * Feature: MediaScanner
 * Function: Scan a MPG file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanVideoMPG_test_012, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideoMPG_test_012");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/video/4.mpg";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a WEBM file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_ScanVideowebm_test_013, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_ScanVideowebm_test_013");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/video/5.webm";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(g_filescanstatus, errCode);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a empty file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scanempty_test_014, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scanempty_test_014");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/empty";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a corrupt file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancorrupt_test_015, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancorrupt_test_015");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/corrupt/corrupt.png";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a flock file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancorrupt_test_016, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancorrupt_test_016");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/flock/flock.png";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_NE(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a file with multiple space in name
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancorrupt_test_017, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancorrupt_test_017");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/data/media/image/1    .png";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a file with canonicalpathimage
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancanonicalpathimage_test_018, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancanonicalpathimage_test_018");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    int errCode = 0;
    string path = "/../../../1.png";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a file with canonicalpathaudio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancanonicalpathaudio_test_019, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancanonicalpathaudio_test_019");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;

    string path = "/../../../1.mp3";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a file with canonicalpathvideo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancanonicalpathvideo_test_020, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancanonicalpathvideo_test_020");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());
    int errCode = 0;
    string path = "/../../../1.mp4";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a file with canonicalpathincorrect
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerModuleTest,  mediascanner_Scancanonicalpathincorrect_test_021, TestSize.Level1)
{
    int result;
    std::string testcaseName("mediascanner_Scancanonicalpathincorrect_test_021");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    HiLog::Info(LABEL, "== TC : %{public}s == ", testcaseName.c_str());

    int errCode = 0;
    string path = "/../../../../1.mp4";
    HiLog::Info(LABEL, "File to be scanned=%{public}s", path.c_str());
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);

    EXPECT_EQ(errCode, result);


    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}
} // namespace Media
} // namespace OHOS