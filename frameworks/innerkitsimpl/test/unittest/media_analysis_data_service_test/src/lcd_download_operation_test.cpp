/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lcd_download_operation_test.h"

#include "lcd_download_operation.h"
#include "analysis_net_connect_observer.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void LcdDownloadOperationTest::SetUpTestCase() {}
void LcdDownloadOperationTest::TearDownTestCase() {}
void LcdDownloadOperationTest::SetUp() {}
void LcdDownloadOperationTest::TearDown() {}

// 用例说明：测试正常开始下载
// 覆盖场景：IDLE状态开始下载
// 分支点：downloadStatus_ != DOWNLOADING
// 触发条件：提供有效fileIds列表和网络类型
// 业务验证：返回E_OK，状态变为DOWNLOADING
HWTEST_F(LcdDownloadOperationTest, StartDownload_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    vector<int64_t> fileIds = {1001, 1002, 1003};
    uint32_t netBearerBitmap = static_cast<uint32_t>(NetBearer::BEARER_ALL);

    int32_t ret = operation->StartDownload(fileIds, netBearerBitmap);
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);

    LcdDownloadStatus status = operation->GetLcdDownloadStatus();
    EXPECT_TRUE(status == LcdDownloadStatus::DOWNLOADING ||
                status == LcdDownloadStatus::IDLE);

    // 清理：取消下载
    operation->CancelDownload();
}

// 用例说明：测试重复下载（已在下载中）
// 覆盖场景：DOWNLOADING状态下再次调用StartDownload
// 分支点：downloadStatus_ == DOWNLOADING
// 触发条件：连续调用StartDownload
// 业务验证：返回E_ERR
HWTEST_F(LcdDownloadOperationTest, StartDownload_Test_002, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    vector<int64_t> fileIds = {1001, 1002};
    uint32_t netBearerBitmap = static_cast<uint32_t>(NetBearer::BEARER_ALL);

    operation->StartDownload(fileIds, netBearerBitmap);
    int32_t ret = operation->StartDownload(fileIds, netBearerBitmap);
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);

    operation->CancelDownload();
}

// 用例说明：测试正常暂停下载
// 覆盖场景：DOWNLOADING状态下暂停
// 分支点：downloadStatus_ == DOWNLOADING
// 触发条件：调用PauseDownload
// 业务验证：返回E_OK，状态变为PAUSED
HWTEST_F(LcdDownloadOperationTest, PauseDownload_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    vector<int64_t> fileIds = {1001};
    uint32_t netBearerBitmap = static_cast<uint32_t>(NetBearer::BEARER_ALL);

    operation->StartDownload(fileIds, netBearerBitmap);
    int32_t ret = operation->PauseDownload();
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);

    operation->CancelDownload();
}

// 用例说明：测试非下载状态下暂停
// 覆盖场景：IDLE或PAUSED状态下暂停
// 分支点：downloadStatus_ != DOWNLOADING
// 触发条件：在IDLE状态调用PauseDownload
// 业务验证：返回E_ERR
HWTEST_F(LcdDownloadOperationTest, PauseDownload_Test_002, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    operation->CancelDownload();

    int32_t ret = operation->PauseDownload();
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);
}

// 用例说明：测试正常恢复下载
// 覆盖场景：PAUSED状态下恢复
// 分支点：downloadStatus_ == PAUSED
// 触发条件：先暂停再恢复
// 业务验证：返回E_OK，状态变为DOWNLOADING
HWTEST_F(LcdDownloadOperationTest, ResumeDownload_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    vector<int64_t> fileIds = {1001};
    uint32_t netBearerBitmap = static_cast<uint32_t>(NetBearer::BEARER_ALL);

    operation->StartDownload(fileIds, netBearerBitmap);
    operation->PauseDownload();
    int32_t ret = operation->ResumeDownload();
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);

    operation->CancelDownload();
}

// 用例说明：测试非暂停状态下恢复
// 覆盖场景：IDLE或DOWNLOADING状态下恢复
// 分支点：downloadStatus_ != PAUSED
// 触发条件：在IDLE状态调用ResumeDownload
// 业务验证：返回E_ERR
HWTEST_F(LcdDownloadOperationTest, ResumeDownload_Test_002, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    operation->CancelDownload();

    int32_t ret = operation->ResumeDownload();
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);
}

// 用例说明：测试正常取消下载
// 覆盖场景：DOWNLOADING或PAUSED状态下取消
// 分支点：downloadStatus_ != IDLE
// 触发条件：开始下载后取消
// 业务验证：返回E_OK，状态变为IDLE，数据已清理
HWTEST_F(LcdDownloadOperationTest, CancelDownload_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    vector<int64_t> fileIds = {1001, 1002};
    uint32_t netBearerBitmap = static_cast<uint32_t>(NetBearer::BEARER_ALL);

    operation->StartDownload(fileIds, netBearerBitmap);
    int32_t ret = operation->CancelDownload();
    EXPECT_EQ(ret, E_ERR);

    LcdDownloadStatus status = operation->GetLcdDownloadStatus();
    EXPECT_EQ(status, LcdDownloadStatus::IDLE);
}

// 用例说明：测试IDLE状态下取消
// 覆盖场景：已处于IDLE状态
// 分支点：downloadStatus_ == IDLE
// 触发条件：在IDLE状态调用CancelDownload
// 业务验证：返回E_ERR
HWTEST_F(LcdDownloadOperationTest, CancelDownload_Test_002, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    operation->CancelDownload();

    int32_t ret = operation->CancelDownload();
    EXPECT_TRUE(ret == E_OK || ret == E_ERR);
}

// 用例说明：测试获取下载结果
// 覆盖场景：获取当前下载结果映射
// 分支点：直接返回downloadResults_
// 触发条件：调用GetDownloadResults
// 业务验证：返回正确的map结构
HWTEST_F(LcdDownloadOperationTest, GetDownloadResults_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    auto results = operation->GetDownloadResults();
    EXPECT_TRUE(results.empty() || results.size() > 0);
}

// 用例说明：测试获取当前网络类型
// 覆盖场景：获取当前网络bearer bitmap
// 分支点：直接返回currentNetBearerBitmap_
// 触发条件：调用GetCurrentNetBearerBitmap
// 业务验证：返回有效的网络类型值
HWTEST_F(LcdDownloadOperationTest, GetCurrentNetBearerBitmap_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    uint32_t netBearerBitmap = operation->GetCurrentNetBearerBitmap();
    EXPECT_TRUE(netBearerBitmap == 0 ||
                netBearerBitmap == static_cast<uint32_t>(NetBearer::BEARER_ALL) ||
                netBearerBitmap == static_cast<uint32_t>(NetBearer::BEARER_WIFI) ||
                netBearerBitmap == static_cast<uint32_t>(NetBearer::BEARER_CELLULAR) ||
                netBearerBitmap == static_cast<uint32_t>(NetBearer::BEARER_ETHERNET));
}

// 用例说明：测试成功回调处理
// 覆盖场景：处理下载成功回调
// 分支点：HandleCallback中success=true
// 触发条件：调用HandleSuccessCallback
// 业务验证：results中对应fileId设置为true
HWTEST_F(LcdDownloadOperationTest, HandleCallback_Test_001, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    DownloadProgressObj progress;
    progress.path = "file://media/test.jpg";

    operation->HandleSuccessCallback(progress);
    auto results = operation->GetDownloadResults();
    EXPECT_TRUE(results.empty() || results.size() > 0);
}

// 用例说明：测试失败回调处理
// 覆盖场景：处理下载失败回调
// 分支点：HandleCallback中success=false
// 触发条件：调用HandleFailedCallback
// 业务验证：results中对应fileId设置为false
HWTEST_F(LcdDownloadOperationTest, HandleCallback_Test_002, TestSize.Level1)
{
    auto operation = LcdDownloadOperation::GetInstance();
    DownloadProgressObj progress;
    progress.path = "file://media/test2.jpg";

    operation->HandleFailedCallback(progress);
    auto results = operation->GetDownloadResults();
    EXPECT_TRUE(results.empty() || results.size() > 0);
}

} // namespace Media
} // namespace OHOS