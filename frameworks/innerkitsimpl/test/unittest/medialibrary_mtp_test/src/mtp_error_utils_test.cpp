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

#include "mtp_error_utils_test.h"
#include "mtp_data_utils.h"
#include "media_mtp_utils.h"
#include "mtp_constants.h"
#include "mtp_error_utils.h"
#include "mtp_packet.h"
#include "medialibrary_errno.h"
#include "mtp_manager.h"
#include "iservice_registry.h"
#include "property.h"
#include <vector>
#include <string>
#include <variant>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MtpErrorUtilsUnitTest::SetUpTestCase(void)
{
    OHOS::Media::MtpManager::GetInstance().mtpMode_ = OHOS::Media::MtpManager::MtpMode::MTP_MODE;
}

void MtpErrorUtilsUnitTest::TearDownTestCase(void) {}
void MtpErrorUtilsUnitTest::SetUp() {}
void MtpErrorUtilsUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibraryMTP
 * Function:
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: mtp_error_utils.cpp test
 */
HWTEST_F(MtpErrorUtilsUnitTest, mtp_packet_001, TestSize.Level1)
{
    shared_ptr<MtpOperationContext> context = make_shared<MtpOperationContext>();
    shared_ptr<MtpPacket> mtpPacket = make_shared<MtpPacket>(context);
    uint16_t ret = mtpPacket->Parser();
    EXPECT_TRUE(ret != MTP_SUCCESS);
    MtpErrorUtils::SolveGetFdError(E_SUCCESS);
    EXPECT_EQ(MtpErrorUtils::SolveGetHandlesError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveGetObjectInfoError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveGetFdError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveSendObjectInfoError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveMoveObjectError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveCopyObjectError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveDeleteObjectError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveObjectPropValueError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTPROPCODE);
    EXPECT_EQ(MtpErrorUtils::SolveCloseFdError(E_EXIST_IN_DB), MTP_ERROR_INVALID_OBJECTHANDLE);
    EXPECT_EQ(MtpErrorUtils::SolveObjectPropValueError(E_HAS_DB_ERROR), MTP_ERROR_INVALID_OBJECTPROP_FORMAT);
    EXPECT_EQ(MtpErrorUtils::SolveCloseFdError(E_HAS_DB_ERROR), MTP_ERROR_STORE_NOT_AVAILABLE);
}
} // namespace Media
} // namespace OHOS