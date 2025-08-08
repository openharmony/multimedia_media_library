/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mtp_file_observer_test.h"
#include "mtp_file_observer.h"
#include <memory>
#include <securec.h>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>
#include "media_log.h"
#include "mtp_manager.h"
#include "mtp_media_library.h"
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpFileObserverTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpFileObserverTest::TearDownTestCase(void) {}
void MtpFileObserverTest::SetUp() {}
void MtpFileObserverTest::TearDown(void) {}

const std::string PATH_SEPARATOR = "/";

struct MoveInfo {
    uint32_t cookie;
    std::string path;
} g_moveInfo;
const std::string REAL_DOCUMENT_FILE = "/storage/media/100/local/files/Docs/Document";
const std::string REAL_STORAGE_FILE = "/storage/media/100/local/files/Docs";

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: EraseFromWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_001, TestSize.Level1)
{
    MtpFileObserver::EraseFromWatchMap(REAL_DOCUMENT_FILE);
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: UpdateWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_002, TestSize.Level1)
{
    MtpFileObserver::UpdateWatchMap(REAL_DOCUMENT_FILE);
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_003, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_DELETE;
    MtpFileObserver::DealWatchMap(event, REAL_DOCUMENT_FILE);
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_004, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_MOVED_TO;
    event.cookie = 0x12345678;
    MtpFileObserver::DealWatchMap(event, REAL_DOCUMENT_FILE);
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_005, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_MOVED_TO;
    event.cookie = 0x12345678;
    MtpFileObserver::DealWatchMap(event, REAL_DOCUMENT_FILE);
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_006, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_MOVED_TO;
    event.cookie = 0x12345678;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEvent(event, REAL_STORAGE_FILE, context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_007, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_MOVED_FROM;
    event.cookie = 0x12345678;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEvent(event, REAL_STORAGE_FILE, context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_008, TestSize.Level1)
{
    inotify_event event;
    event.mask = IN_CLOSE_WRITE;
    event.cookie = 0x12345678;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEvent(event, REAL_STORAGE_FILE, context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_009, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x400002C0;
    event.cookie = 0x12345678;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEvent(event, REAL_STORAGE_FILE, context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0010, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x000003C8;
    event.cookie = 0x12345678;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEvent(event, REAL_STORAGE_FILE, context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendBattery
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0012, TestSize.Level1)
{
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendBattery(context);
    MtpFileObserver::isRunning_ = false;
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StartFileInotify
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0014, TestSize.Level1)
{
    std::shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    ASSERT_NE(mtpFileObserver, nullptr);
    EXPECT_TRUE(mtpFileObserver->StartFileInotify());
    mtpFileObserver->StopFileInotify();
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: WatchPathThread
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0015, TestSize.Level1)
{
    MtpFileObserver::isRunning_ = false;
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddFileInotify
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0016, TestSize.Level1)
{
    std::shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    ASSERT_NE(mtpFileObserver, nullptr);
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpFileObserver->StartFileInotify();
    mtpFileObserver->startThread_ = false;
    mtpFileObserver->inotifySuccess_ = true;
    mtpFileObserver->AddFileInotify(REAL_STORAGE_FILE, REAL_DOCUMENT_FILE, context);
    mtpFileObserver->StopFileInotify();
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: EraseFromWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0017, TestSize.Level1)
{
    std::shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    ASSERT_NE(mtpFileObserver, nullptr);
    ContextSptr context = make_shared<MtpOperationContext>();
    ASSERT_NE(context, nullptr);
    mtpFileObserver->StartFileInotify();
    MtpFileObserver::EraseFromWatchMap(REAL_DOCUMENT_FILE);
    mtpFileObserver->StopFileInotify();
    EXPECT_TRUE(MtpFileObserver::WatchPathThread(context));
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: EraseFromWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0018, TestSize.Level1)
{
    std::shared_ptr<MtpFileObserver> mtpFileObserver = std::make_shared<MtpFileObserver>();
    ASSERT_NE(mtpFileObserver, nullptr);

    std::string path = "/file/Docs";

    MtpFileObserver::watchMap_.insert(std::pair<int, std::string>(1, "/file/Docs/1.jpg"));
    MtpFileObserver::watchMap_.insert(std::pair<int, std::string>(1, "/file/Docs/"));

    mtpFileObserver->EraseFromWatchMap(path);
    EXPECT_TRUE(MtpFileObserver::watchMap_.empty());
}


/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0019, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x40000200;
    std::string path = "/file/Docs";

    MtpFileObserver::watchMap_.insert(std::pair<int, std::string>(1, "/file/Docs/1.jpg"));
    MtpFileObserver::watchMap_.insert(std::pair<int, std::string>(1, "/file/Docs/"));

    MtpFileObserver::DealWatchMap(event, path);
    EXPECT_TRUE(MtpFileObserver::watchMap_.empty());
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0020, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x40000040;
    std::string path = "/file/Docs";

    MtpFileObserver::DealWatchMap(event, path);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0021, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x40000080;
    std::string path = "/file/Docs";

    MtpFileObserver::DealWatchMap(event, path);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: DealWatchMap
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0022, TestSize.Level1)
{
    inotify_event event;
    event.mask = 0x40000000;
    std::string path = "/file/Docs";

    MtpFileObserver::DealWatchMap(event, path);
}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEvent
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0023, TestSize.Level1)
{
    inotify_event event;
    std::string path = "/file/Docs";
    ContextSptr context = std::make_shared<MtpOperationContext>();
    MtpFileObserver::isEventThreadRunning_.store(false);
    ASSERT_NE(context, nullptr);
    event.mask = 0x00000100;
    MtpFileObserver::SendEvent(event, path, context);

    ASSERT_NE(context, nullptr);
    event.mask = 0x00000080;
    MtpFileObserver::SendEvent(event, path, context);

    ASSERT_NE(context, nullptr);
    event.mask = 0x00000008;
    MtpFileObserver::SendEvent(event, path, context);

    ASSERT_NE(context, nullptr);
    event.mask = 0x00000200;
    MtpFileObserver::SendEvent(event, path, context);

    ASSERT_NE(context, nullptr);
    event.mask = 0x00000040;
    MtpFileObserver::SendEvent(event, path, context);
}

/*
 * Feature: MediaLibraryMTP
 * Function: StopFileInotify
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: StopFileInotify success
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0024, TestSize.Level1)
{
    std::shared_ptr<MtpFileObserver> mtpFileObserver = make_shared<MtpFileObserver>();
    ASSERT_NE(mtpFileObserver, nullptr);
    MtpFileObserver::isRunning_ = true;
    MtpFileObserver::watchMap_.clear();
    EXPECT_TRUE(mtpFileObserver->StopFileInotify());
}

/*
 * Feature: MediaLibraryMTP
 * Function: AddToQueue
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: AddToQueue success
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0025, TestSize.Level1)
{
    MtpFileObserver::StopSendEventThread();
    MtpFileObserver::isEventThreadRunning_.store(true);
    MtpFileObserver::AddToQueue(MTP_EVENT_OBJECT_ADDED_CODE, 0);
    EXPECT_EQ(MtpFileObserver::eventQueue_.size(), 1);
    MtpFileObserver::StopSendEventThread();
}

/*
 * Feature: MediaLibraryMTP
 * Function: SendEventThread
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: SendEventThread with isEventThreadRunning_ false
 */
HWTEST_F(MtpFileObserverTest, mtp_file_observer_test_0027, TestSize.Level1)
{
    MtpFileObserver::StopSendEventThread();
    MtpFileObserver::isEventThreadRunning_.store(true);
    MtpFileObserver::AddToQueue(MTP_EVENT_OBJECT_ADDED_CODE, 0);
    ContextSptr context = make_shared<MtpOperationContext>();
    MtpFileObserver::isEventThreadRunning_.store(false);
    ASSERT_NE(context, nullptr);
    MtpFileObserver::SendEventThread(context);
    EXPECT_EQ(MtpFileObserver::eventQueue_.size(), 1);
    MtpFileObserver::StopSendEventThread();
}
} // namespace Media
} // namespace OHOS