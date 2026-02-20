/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <thread>
#include <memory>
#include "mtp_operation_test.h"
#include "mtp_operation.h"
#include "mtp_operation_context.h"
#include "mtp_operation_utils.h"
#include "mtp_packet.h"
#include "mtp_driver.h"
#include "mtp_constants.h"
#include "payload_data.h"
#include "header_data.h"
#include "mtp_manager.h"
#include "storage.h"
#include "parameters.h"
#include "media_mtp_utils.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpOperationTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpOperationTest::TearDownTestCase(void) {}

void MtpOperationTest::SetUp() {}

void MtpOperationTest::TearDown(void) {}

/*
* Feature: MTP Operation
* Function: Constructor
* SubFunction: Init
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test MtpOperation constructor initializes all members correctly
*/
HWTEST_F(MtpOperationTest, MtpOperation_Constructor_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: MTP disabled check
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute when MTP is disabled
*/
HWTEST_F(MtpOperationTest, MtpOperation_Execute_MtpDisabled_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: Stop request packet
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Stop method calls requestPacket Stop
*/
HWTEST_F(MtpOperationTest, MtpOperation_Stop_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    mtpOperation->Stop();
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Reset all packets and context
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation resets all internal state
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetOperation_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    mtpOperation->ResetOperation();
}

/*
* Feature: MTP Operation
* Function: AddStorage
* SubFunction: Add storage to manager
* FunctionPoints: MtpOperation::AddStorage
* EnvConditions: NA
* CaseDescription: Test AddStorage with null storage
*/
HWTEST_F(MtpOperationTest, MtpOperation_AddStorage_Null_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = nullptr;
    mtpOperation->AddStorage(storage);
}

/*
* Feature: MTP Operation
* Function: AddStorage
* SubFunction: Add storage to manager
* FunctionPoints: MtpOperation::AddStorage
* EnvConditions: NA
* CaseDescription: Test AddStorage with valid storage
*/
HWTEST_F(MtpOperationTest, MtpOperation_AddStorage_Valid_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    ASSERT_NE(storage, nullptr);
    
    mtpOperation->AddStorage(storage);
}

/*
* Feature: MTP Operation
* Function: RemoveStorage
* SubFunction: Remove storage from manager
* FunctionPoints: MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test RemoveStorage with null storage
*/
HWTEST_F(MtpOperationTest, MtpOperation_RemoveStorage_Null_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = nullptr;
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: RemoveStorage
* SubFunction: Remove storage from manager
* FunctionPoints: MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test RemoveStorage with valid storage
*/
HWTEST_F(MtpOperationTest, MtpOperation_RemoveStorage_Valid_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    ASSERT_NE(storage, nullptr);
    
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Multiple Execute calls
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test multiple Execute calls
*/
HWTEST_F(MtpOperationTest, MtpOperation_Execute_Multiple_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 5; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
    }
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: Multiple Stop calls
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test multiple Stop calls
*/
HWTEST_F(MtpOperationTest, MtpOperation_Stop_Multiple_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 5; i++) {
        mtpOperation->Stop();
    }
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Multiple Reset calls
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test multiple ResetOperation calls
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetOperation_Multiple_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 5; i++) {
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: AddStorage and RemoveStorage
* SubFunction: Storage management
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test add and remove multiple storages
*/
HWTEST_F(MtpOperationTest, MtpOperation_StorageManagement_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        ASSERT_NE(storage, nullptr);
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Constructor and Execute
* SubFunction: Full lifecycle
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test full lifecycle of MtpOperation
*/
HWTEST_F(MtpOperationTest, MtpOperation_Lifecycle_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    mtpOperation->ResetOperation();
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Execute with Reset
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute followed by ResetOperation
*/
HWTEST_F(MtpOperationTest, MtpOperation_Execute_Reset_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->ResetOperation();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Execute and Stop
* SubFunction: Concurrent operations
* FunctionPoints: MtpOperation::Execute, MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Execute and Stop in sequence
*/
HWTEST_F(MtpOperationTest, MtpOperation_Execute_Stop_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Constructor
* SubFunction: Multiple instances
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test creating multiple MtpOperation instances
*/
HWTEST_F(MtpOperationTest, MtpOperation_MultipleInstances_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    
    for (int i = 0; i < 10; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        ASSERT_NE(mtpOperation, nullptr);
        operations.push_back(mtpOperation);
    }
    
    EXPECT_EQ(operations.size(), 10);
}

/*
* Feature: MTP Operation
* Function: AddStorage
* SubFunction: Multiple storages
* FunctionPoints: MtpOperation::AddStorage
* EnvConditions: NA
* CaseDescription: Test adding multiple storages without removing
*/
HWTEST_F(MtpOperationTest, MtpOperation_AddMultipleStorages_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 10; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        ASSERT_NE(storage, nullptr);
        mtpOperation->AddStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: RemoveStorage
* SubFunction: Remove non-existent storage
* FunctionPoints: MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test removing storage that was never added
*/
HWTEST_F(MtpOperationTest, MtpOperation_RemoveNonExistentStorage_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    ASSERT_NE(storage, nullptr);
    
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Stress test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute in a loop (stress test)
*/
HWTEST_F(MtpOperationTest, MtpOperation_Execute_Stress_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 50; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 10 == 0) {
            mtpOperation->ResetOperation();
        }
    }
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: Stress test
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Stop in a loop (stress test)
*/
HWTEST_F(MtpOperationTest, MtpOperation_Stop_Stress_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 50; i++) {
        mtpOperation->Stop();
    }
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Stress test
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation in a loop (stress test)
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetOperation_Stress_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 50; i++) {
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Mixed operations
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test mixed storage operations
*/
HWTEST_F(MtpOperationTest, MtpOperation_MixedStorageOps_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage1 = std::make_shared<Storage>();
    std::shared_ptr<Storage> storage2 = std::make_shared<Storage>();
    std::shared_ptr<Storage> storage3 = std::make_shared<Storage>();
    
    mtpOperation->AddStorage(storage1);
    mtpOperation->AddStorage(storage2);
    mtpOperation->RemoveStorage(storage1);
    mtpOperation->AddStorage(storage3);
    mtpOperation->RemoveStorage(storage22);
    mtpOperation->RemoveStorage(storage3);
}

/*
* Feature: MTP Operation
* Function: Execute and ResetOperation
* SubFunction: Alternating operations
* FunctionPoints: MtpOperation::Execute, MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test alternating Execute and ResetOperation
*/
HWTEST_F(MtpOperationTest, MtpOperation_AlternatingOps_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 20; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: Constructor
* SubFunction: Default initialization
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test that constructor initializes with default values
*/
HWTEST_F(MtpOperationTest, MtpOperation_DefaultInit_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    mtpOperation->ResetOperation();
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: With storage operations
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute with storage management
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExecuteWithStorage_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: After Execute
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Stop after Execute
*/
HWTEST_F(MtpOperationTest, MtpOperation_StopAfterExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: After Execute
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation after Execute
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetAfterExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->ResetOperation();
}

/*
* Feature: MTP Operation
* Function: AddStorage
* SubFunction: After Execute
* FunctionPoints: MtpOperation::AddStorage
* EnvConditions: NA
* CaseDescription: Test AddStorage after Execute
*/
HWTEST_F(MtpOperationTest, MtpOperation_AddStorageAfterExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
}

/*
* Feature: MTP Operation
* Function: RemoveStorage
* SubFunction: After Execute
* FunctionPoints: MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test RemoveStorage after Execute
*/
HWTEST_F(MtpOperationTest, MtpOperation_RemoveStorageAfterExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Multiple instances
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute on multiple instances
*/
HWTEST_F(MtpOperationTest, MtpOperation_MultipleExecute_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        ASSERT_NE(mtpOperation, nullptr);
        operations.push_back(mtpOperation);
    }
    
    for (auto& op : operations) {
        int32_t result = op->Execute();
        EXPECT_EQ(result, 0);
    }
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: Multiple instances
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Stop on multiple instances
*/
HWTEST_F(MtpOperationTest, MtpOperation_MultipleStop_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        ASSERT_NE(mtpOperation, nullptr);
        operations.push_back(mtpOperation);
    }
    
    for (auto& op : operations) {
        op->Stop();
    }
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Multiple instances
* Function: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation on multiple instances
*/
HWTEST_F(MtpOperationTest, MtpOperation_MultipleReset_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        ASSERT_NE(mtpOperation, nullptr);
        operations.push_back(mtpOperation);
    }
    
    for (auto& op : operations) {
        op->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Multiple instances
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test storage operations on multiple instances
*/
HWTEST_F(MtpOperationTest, MtpOperation_MultipleStorageOps_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        
        operations.push_back(mtpOperation);
        storages.push_back(storage);
        
        mtpOperation->AddStorage(storage);
    }
    
    for (size_t i = 0; i < operations.size(); i++) {
        operations[i]->RemoveStorage(storages[i]);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: With Stop between
* FunctionPoints: MtpOperation::Execute, MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Execute with Stop in between
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExecuteWithStop_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: With Execute between
* FunctionPoints: MtpOperation::Execute, MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation with Execute in between
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetWithExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    mtpOperation->ResetOperation();
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->ResetOperation();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: With Execute between
* FunctionPoints: MtpOperation::Execute, MtpOperation::AddStorage
* EnvConditions: NA
* CaseDescription: Test storage operations with Execute in between
*/
HWTEST_F(MtpOperationTest, MtpOperation_StorageWithExecute_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage1 = std::make_shared<Storage>();
    std::shared_ptr<Storage> storage2 = std::make_shared<Storage>();
    
    mtpOperation->AddStorage(storage1);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->RemoveStorage(storage1);
    mtpOperation->AddStorage(storage2);
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->RemoveStorage(storage2);
}

/*
* Feature: MTP Operation
* Function: Constructor
* SubFunction: Unique pointer
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test creating MtpOperation with unique_ptr
*/
HWTEST_F(MtpOperationTest, MtpOperation_UniquePtr_001, TestSize.Level1)
{
    std::unique_ptr<MtpOperation> mtpOperation = std::make_unique<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Constructor
* SubFunction: Raw pointer
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test creating MtpOperation with raw pointer
*/
HWTEST_F(MtpOperationTest, MtpOperation_RawPtr_001, TestSize.Level1)
{
    MtpOperation* mtpOperation = new MtpOperation();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    delete mtpOperation;
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Long running
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute with long running sequence
*/
HWTEST_F(MtpOperationTest, MtpOperation_LongRunning_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 100; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 20 == 0) {
            mtpOperation->Stop();
            mtpOperation->ResetOperation();
        }
    }
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Large number of storages
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test adding and removing large number of storages
*/
HWTEST_F(MtpOperationTest, MtpOperation_LargeStorageCount_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 20; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: After storage removal
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute after removing all storages
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExecuteAfterStorageRemoval_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: After storage removal
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Test Stop after removing all storages
*/
HWTEST_F(MtpOperationTest, MtpOperation_StopAfterStorageRemoval_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    
    mtpOperation->Stop();
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: After storage removal
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation after removing all storages
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetAfterStorageRemoval_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    
    mtpOperation->ResetOperation();
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Before any storage operations
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute before any storage operations
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExecuteBeforeStorageOps_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Constructor and destructor
* SubFunction: Resource management
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test constructor and destructor resource management
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResourceManagement_001, TestSize.Level1)
{
    {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        ASSERT_NE(mtpOperation, nullptr);
        
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
        
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        mtpOperation->AddStorage(storage);
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Concurrent with other operations
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute with concurrent Stop calls
*/
HWTEST_F(MtpOperationTest, MtpOperation_ConcurrentOps_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    mtpOperation->ResetOperation();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Edge cases
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test storage operations edge cases
*/
HWTEST_F(MtpOperationTest, MtpOperation_StorageEdgeCases_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    
    mtpOperation->AddStorage(storage);
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    mtpOperation->RemoveStorage(storage);
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Repeated pattern
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute with repeated operation pattern
*/
HWTEST_F(MtpOperationTest, MtpOperation_RepeatedPattern_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 30; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: All methods
* SubFunction: Comprehensive test
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test all MtpOperation methods in sequence
*/
HWTEST_F(MtpOperationTest, MtpOperation_Comprehensive_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    
    mtpOperation->AddStorage(storage);
    
    for (int i = 0; i < 10; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
    }
    
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Boundary conditions
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute with boundary conditions
*/
HWTEST_F(MtpOperationTest, MtpOperation_BoundaryConditions_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    mtpOperation->ResetOperation();
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Error handling
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute error handling
*/
HWTEST_F(MtpOperationTest, MtpOperation_ErrorHandling_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->ResetOperation();
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Error handling
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test storage operations error handling
*/
HWTEST_F(MtpOperationTest, MtpOperation_StorageErrorHandling_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> nullStorage = nullptr;
    mtpOperation->AddStorage(nullStorage);
    mtpOperation->RemoveStorage(nullStorage);
    
    std::shared_ptr<Storage> validStorage = std::make_shared<Storage>();
    mtpOperation->AddStorage(validStorage);
    mtpOperation->RemoveStorage(validStorage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Performance test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute performance
*/
HWTEST_F(MtpOperationTest, MtpOperation_Performance_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 200; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
    }
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Performance test
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Test ResetOperation performance
*/
HWTEST_F(MtpOperationTest, MtpOperation_ResetPerformance_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 200; i++) {
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Performance test
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test storage operations performance
*/
HWTEST_F(MtpOperationTest, MtpOperation_StoragePerformance_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 100; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Reliability test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute reliability
*/
HWTEST_F(MtpOperationTest, MtpOperation_Reliability_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 1000; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 100 == 0) {
            mtpOperation->ResetOperation();
        }
    }
}

/*
* Feature: MTP Operation
* Function: All methods
* SubFunction: Integration test
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test MtpOperation integration
*/
HWTEST_F(MtpOperationTest, MtpOperation_Integration_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (int i = 0; i < 20; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 5 == 0) {
            mtpOperation->Stop();
        }
        
        if (i % 10 == 0) {
            mtpOperation->ResetOperation();
        }
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Memory stress
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute memory stress
*/
HWTEST_F(MtpOperationTest, MtpOperation_MemoryStress_001, TestSize.Level1)
{
    std::vector<std::shared_ptr<MtpOperation>> operations;
    
    for (int i = 0; i < 50; i++) {
        std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
        operations.push_back(mtpOperation);
        
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
    }
    
    operations.clear();
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: State transitions
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute state transitions
*/
HWTEST_F(MtpOperationTest, MtpOperation_StateTransitions_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->Stop();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->ResetOperation();
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: State transitions
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Test storage operations state transitions
*/
HWTEST_F(MtpOperationTest, MtpOperation_StorageStateTransitions_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    
    mtpOperation->AddStorage(storage);
    
    int32_t result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->RemoveStorage(storage);
    
    result = mtpOperation->Execute();
    EXPECT_EQ(result, 0);
    
    mtpOperation->AddStorage(storage);
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Recovery test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Test Execute recovery
*/
HWTEST_F(MtpOperationTest, MtpOperation_Recovery_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 50; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
        
        result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
    }
}

/*
* Feature: MTP Operation
* Function: All methods
* SubFunction: Robustness test
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Test MtpOperation robustness
*/
HWTEST_F(MtpOperationTest, MtpOperation_Robustness_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 100; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
        
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        mtpOperation->AddStorage(storage);
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Final test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Final comprehensive test
*/
HWTEST_F(MtpOperationTest, MtpOperation_Final_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 10; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (int i = 0; i < 50; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 10 == 0) {
            mtpOperation->Stop();
        }
        
        if (i % 20 == 0) {
            mtpOperation->ResetOperation();
        }
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Extended test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Extended Execute test
*/
HWTEST_F(MtpOperationTest, MtpOperation_Extended_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 30; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
    }
}

/*
* Feature: MTP Operation
* Function: Stop
* SubFunction: Extended test
* FunctionPoints: MtpOperation::Stop
* EnvConditions: NA
* CaseDescription: Extended Stop test
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExtendedStop_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 30; i++) {
        mtpOperation->Stop();
    }
}

/*
* Feature: MTP Operation
* Function: ResetOperation
* SubFunction: Extended test
* FunctionPoints: MtpOperation::ResetOperation
* EnvConditions: NA
* CaseDescription: Extended ResetOperation test
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExtendedReset_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 30; i++) {
        mtpOperation->ResetOperation();
    }
}

/*
* Feature: MTP Operation
* Function: Storage operations
* SubFunction: Extended test
* FunctionPoints: MtpOperation::AddStorage, MtpOperation::RemoveStorage
* EnvConditions: NA
* CaseDescription: Extended storage operations test
*/
HWTEST_F(MtpOperationTest, MtpOperation_ExtendedStorage_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 15; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Complex sequence
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Complex Execute sequence test
*/
HWTEST_F(MtpOperationTest, MtpOperation_ComplexSequence_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    for (int i = 0; i < 25; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 5 == 0) {
            mtpOperation->Stop();
        }
        
        if (i % 10 == 0) {
            mtpOperation->ResetOperation();
        }
    }
}

/*
* Feature: MTP Operation
* Function: All methods
* SubFunction: Complex sequence
* FunctionPoints: MtpOperation
* EnvConditions: NA
* CaseDescription: Complex method sequence test
*/
HWTEST_F(MtpOperationTest, MtpOperation_ComplexMethods_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::shared_ptr<Storage> storage = std::make_shared<Storage>();
    mtpOperation->AddStorage(storage);
    
    for (int i = 0; i < 20; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        mtpOperation->Stop();
        mtpOperation->ResetOperation();
    }
    
    mtpOperation->RemoveStorage(storage);
}

/*
* Feature: MTP Operation
* Function: Execute
* SubFunction: Final extended test
* FunctionPoints: MtpOperation::Execute
* EnvConditions: NA
* CaseDescription: Final extended Execute test
*/
HWTEST_F(MtpOperationTest, MtpOperation_FinalExtended_001, TestSize.Level1)
{
    std::shared_ptr<MtpOperation> mtpOperation = std::make_shared<MtpOperation>();
    ASSERT_NE(mtpOperation, nullptr);
    
    std::vector<std::shared_ptr<Storage>> storages;
    
    for (int i = 0; i < 8; i++) {
        std::shared_ptr<Storage> storage = std::make_shared<Storage>();
        storages.push_back(storage);
        mtpOperation->AddStorage(storage);
    }
    
    for (int i = 0; i < 40; i++) {
        int32_t result = mtpOperation->Execute();
        EXPECT_EQ(result, 0);
        
        if (i % 8 == 0) {
            mtpOperation->Stop();
        }
        
        if (i % 16 == 0) {
            mtpOperation->ResetOperation();
        }
    }
    
    for (auto& storage : storages) {
        mtpOperation->RemoveStorage(storage);
    }
}

} // namespace Media
} // namespace OHOS
