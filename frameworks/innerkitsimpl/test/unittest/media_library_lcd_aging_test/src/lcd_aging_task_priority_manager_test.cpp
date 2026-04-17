/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "lcd_aging_task_priority_manager_test.h"

#include <chrono>
#include <thread>

#include "lcd_aging_task_priority_manager.h"
#include "lcd_aging_worker.h"
#include "media_log.h"
#include "medialibrary_astc_stat.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Media;

void LcdAgingTaskPriorityManagerTest::SetUpTestCase(void) {}

void LcdAgingTaskPriorityManagerTest::TearDownTestCase(void) {}

void LcdAgingTaskPriorityManagerTest::SetUp()
{
    LcdAgingWorker::GetInstance().isThreadRunning_.store(true);
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.taskCounters_.clear();
    manager.hasHighPriorityTasks_.store(false);
}

void LcdAgingTaskPriorityManagerTest::TearDown(void)
{
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.taskCounters_.clear();
    manager.hasHighPriorityTasks_.store(false);
    LcdAgingWorker::GetInstance().isThreadRunning_.store(false);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, RegisterHighPriorityTask_WorkerNotRunning_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("RegisterHighPriorityTask_WorkerNotRunning_test_001: test register task when worker not running");
    LcdAgingWorker::GetInstance().isThreadRunning_.store(false);
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, RegisterHighPriorityTask_Success_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("RegisterHighPriorityTask_Success_test_001: test register task successfully");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 1);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, RegisterHighPriorityTask_MultipleSameType_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("RegisterHighPriorityTask_MultipleSameType_test_001: test register multiple tasks of same type");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 3);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, RegisterHighPriorityTask_DifferentTypes_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("RegisterHighPriorityTask_DifferentTypes_test_001: test register tasks of different types");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::ANALYSIS_DOWNLOAD);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 1);
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::ANALYSIS_DOWNLOAD], 1);
    EXPECT_EQ(manager.taskCounters_.size(), 2);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, UnregisterHighPriorityTask_WorkerNotRunning_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UnregisterHighPriorityTask_WorkerNotRunning_test_001: test unregister task when not running");
    LcdAgingWorker::GetInstance().isThreadRunning_.store(false);
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, UnregisterHighPriorityTask_Success_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UnregisterHighPriorityTask_Success_test_001: test unregister task successfully");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, UnregisterHighPriorityTask_NotExistType_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UnregisterHighPriorityTask_NotExistType_test_001: test unregister non-existent task type");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, UnregisterHighPriorityTask_MultipleUnregister_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UnregisterHighPriorityTask_MultipleUnregister_test_001: test multiple unregister calls");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 3);
    
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 2);
    
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_[HighPriorityTaskType::CLOUD_PULL], 1);
    
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, UnregisterHighPriorityTask_DifferentTypes_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UnregisterHighPriorityTask_DifferentTypes_test_001: test unregister different task types");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::ANALYSIS_DOWNLOAD);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 2);
    
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 1);
    
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::ANALYSIS_DOWNLOAD);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, HasHighPriorityTasks_InitiallyFalse_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HasHighPriorityTasks_InitiallyFalse_test_001: test initial state has no high priority tasks");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, HasHighPriorityTasks_AfterRegister_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HasHighPriorityTasks_AfterRegister_test_001: test has high priority tasks after register");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, HasHighPriorityTasks_AfterUnregister_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("HasHighPriorityTasks_AfterUnregister_test_001: test no high priority tasks after unregister");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, Reset_Success_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Reset_Success_test_001: test reset clears all task counters");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    manager.RegisterHighPriorityTask(HighPriorityTaskType::ANALYSIS_DOWNLOAD);
    EXPECT_TRUE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 2);
    
    manager.Reset();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, Reset_EmptyCounters_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("Reset_EmptyCounters_test_001: test reset when counters already empty");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
    manager.Reset();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    EXPECT_EQ(manager.taskCounters_.size(), 0);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, CheckForHighPriorityTasks_NoTasks_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckForHighPriorityTasks_NoTasks_test_001: test check returns true when no tasks exist");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
    bool result = manager.CheckForHighPriorityTasks();
    EXPECT_TRUE(result);
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, CheckForHighPriorityTasks_MultipleThreads_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("CheckForHighPriorityTasks_MultipleThreads_test_001: test thread safety with multiple threads");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    
    thread thread1([&manager]() {
        this_thread::sleep_for(chrono::milliseconds(50));
        manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
    });
    
    thread thread2([&manager]() {
        bool result = manager.CheckForHighPriorityTasks();
        EXPECT_TRUE(result);
    });
    
    thread1.join();
    thread2.join();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}

HWTEST_F(LcdAgingTaskPriorityManagerTest, ThreadSafety_RegisterAndUnregister_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("ThreadSafety_RegisterAndUnregister_test_001: test thread safety with register/unregister");
    auto& manager = LcdAgingTaskPriorityManager::GetInstance();
    
    thread registerThread1([&manager]() {
        for (int i = 0; i < 100; i++) {
            manager.RegisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
            this_thread::sleep_for(chrono::milliseconds(1));
        }
    });
    
    thread registerThread2([&manager]() {
        for (int i = 0; i < 100; i++) {
            manager.RegisterHighPriorityTask(HighPriorityTaskType::ANALYSIS_DOWNLOAD);
            this_thread::sleep_for(chrono::milliseconds(1));
        }
    });
    
    thread unregisterThread([&manager]() {
        for (int i = 0; i < 100; i++) {
            manager.UnregisterHighPriorityTask(HighPriorityTaskType::CLOUD_PULL);
            this_thread::sleep_for(chrono::milliseconds(1));
        }
    });
    
    registerThread1.join();
    registerThread2.join();
    unregisterThread.join();
    
    manager.Reset();
    EXPECT_FALSE(manager.HasHighPriorityTasks());
}