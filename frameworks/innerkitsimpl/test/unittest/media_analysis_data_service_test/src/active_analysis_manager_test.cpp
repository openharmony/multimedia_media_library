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

#define MLOG_TAG "ActiveAnalysisManagerTest"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-ext.h>
#include <gtest/hwext/gtest-tag.h>

#include "active_analysis_manager.h"
#include "media_library_error_code.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
using namespace testing::ext;
using namespace OHOS::Media::AnalysisData;

namespace {
constexpr int32_t FIRST_VALID_ANALYSIS_TYPE = static_cast<int32_t>(ANALYSIS_TYPE_START) + 1;
constexpr int32_t LAST_VALID_ANALYSIS_TYPE = static_cast<int32_t>(ANALYSIS_TYPE_END) - 1;
constexpr size_t MAX_ACTIVE_ANALYSIS_FILE_ID_COUNT = 100;
constexpr size_t MAX_ACTIVE_ANALYSIS_PARAM_LENGTH = 500;

class FakeRemoteObject final : public IRemoteObject {
public:
    explicit FakeRemoteObject(std::u16string descriptor = u"mock_i_remote_object")
        : IRemoteObject(std::move(descriptor))
    {
    }

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        lastRequestCode_ = code;
        lastInterfaceToken_ = data.ReadInterfaceToken();
        ++sendRequestCount_;
        return E_OK;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return {};
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    uint32_t GetLastRequestCode() const
    {
        return lastRequestCode_;
    }

    int32_t GetSendRequestCount() const
    {
        return sendRequestCount_;
    }

private:
    uint32_t lastRequestCode_ = 0;
    int32_t sendRequestCount_ = 0;
    std::u16string lastInterfaceToken_;
};

class FakeActiveAnalysisRemoteInvoker final : public ActiveAnalysisRemoteInvoker {
public:
    sptr<IRemoteObject> GetSaRemote() const override
    {
        return saRemote_;
    }

    int32_t StartActiveAnalysis(const StartActiveAnalysisDto &dto) const override
    {
        ++startCallCount_;
        lastStartDto_ = dto;
        return startResult_;
    }

    int32_t StopActiveAnalysis(const StopActiveAnalysisDto &dto) const override
    {
        ++stopCallCount_;
        lastStopDto_ = dto;
        return stopResult_;
    }

    void SetSaRemote(const sptr<IRemoteObject> &remote)
    {
        saRemote_ = remote;
    }

    void SetStartResult(int32_t result)
    {
        startResult_ = result;
    }

    int32_t GetStartCallCount() const
    {
        return startCallCount_;
    }

    int32_t GetStopCallCount() const
    {
        return stopCallCount_;
    }

    const StartActiveAnalysisDto &GetLastStartDto() const
    {
        return lastStartDto_;
    }

    const StopActiveAnalysisDto &GetLastStopDto() const
    {
        return lastStopDto_;
    }

private:
    mutable int32_t startCallCount_ = 0;
    mutable int32_t stopCallCount_ = 0;
    mutable StartActiveAnalysisDto lastStartDto_;
    mutable StopActiveAnalysisDto lastStopDto_;
    sptr<IRemoteObject> saRemote_ = new FakeRemoteObject(u"mock_sa_remote_object");
    int32_t startResult_ = E_OK;
    int32_t stopResult_ = E_OK;
};

StartActiveAnalysisDto BuildStartDto(const sptr<IRemoteObject> &callbackRemote)
{
    StartActiveAnalysisDto dto;
    dto.analysisTypes = { static_cast<int32_t>(ANALYSIS_SELECTED) };
    dto.fileIds = { "2", "1", "1" };
    dto.param = R"({"requestId":"start-1"})";
    dto.callbackRemote = callbackRemote;
    return dto;
}

StopActiveAnalysisDto BuildStopDto()
{
    StopActiveAnalysisDto dto;
    dto.analysisTypes = { static_cast<int32_t>(ANALYSIS_SELECTED) };
    dto.fileIds = { "1", "2" };
    dto.param = R"({"requestId":"stop-1"})";
    return dto;
}
} // namespace

class ActiveAnalysisManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        invoker_ = std::make_shared<FakeActiveAnalysisRemoteInvoker>();
        manager_ = std::make_unique<ActiveAnalysisManager>(invoker_);
    }

protected:
    std::shared_ptr<FakeActiveAnalysisRemoteInvoker> invoker_;
    std::unique_ptr<ActiveAnalysisManager> manager_;
};

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsUnsupportedType, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.analysisTypes = { 100 };
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskAcceptsBoundaryTypes, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.analysisTypes = {
        FIRST_VALID_ANALYSIS_TYPE,
        LAST_VALID_ANALYSIS_TYPE
    };
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(resultCode, E_OK);
    EXPECT_EQ(saRemote, invoker_->GetSaRemote());
    EXPECT_EQ(invoker_->GetStartCallCount(), 1);
    EXPECT_EQ(invoker_->GetLastStartDto().analysisTypes, dto.analysisTypes);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsOversizedTypes, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.analysisTypes.clear();
    for (int32_t analysisType = FIRST_VALID_ANALYSIS_TYPE; analysisType <= LAST_VALID_ANALYSIS_TYPE; ++analysisType) {
        dto.analysisTypes.push_back(analysisType);
    }
    dto.analysisTypes.push_back(FIRST_VALID_ANALYSIS_TYPE);
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsNullCallback, TestSize.Level1)
{
    StartActiveAnalysisDto dto;
    dto.analysisTypes = { static_cast<int32_t>(ANALYSIS_SELECTED) };
    dto.fileIds = { "1" };
    dto.param = R"({"requestId":"null-callback"})";
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskAcceptsEmptyFileIds, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.fileIds.clear();
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(resultCode, E_OK);
    EXPECT_EQ(saRemote, invoker_->GetSaRemote());
    EXPECT_EQ(invoker_->GetStartCallCount(), 1);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsInvalidFileId, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.fileIds = { "abc" };
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsOversizedFileIds, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.fileIds.assign(MAX_ACTIVE_ANALYSIS_FILE_ID_COUNT + 1, "1");
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsOversizedParam, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    dto.param.assign(MAX_ACTIVE_ANALYSIS_PARAM_LENGTH + 1, 'a');
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRejectsMissingSaRemote, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    int32_t resultCode = E_OK;
    sptr<IRemoteObject> saRemote;

    invoker_->SetSaRemote(nullptr);
    int32_t ret = manager_->SubmitTask(dto, resultCode, saRemote);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR);
    EXPECT_EQ(saRemote, nullptr);
    EXPECT_EQ(invoker_->GetStartCallCount(), 1);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskForwardsRepeatedRequests, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    int32_t firstResult = E_OK;
    int32_t secondResult = E_OK;
    sptr<IRemoteObject> firstSaRemote;
    sptr<IRemoteObject> secondSaRemote;

    EXPECT_EQ(manager_->SubmitTask(dto, firstResult, firstSaRemote), E_OK);
    EXPECT_EQ(manager_->SubmitTask(dto, secondResult, secondSaRemote), E_OK);
    EXPECT_EQ(firstResult, E_OK);
    EXPECT_EQ(secondResult, E_OK);
    EXPECT_EQ(firstSaRemote, invoker_->GetSaRemote());
    EXPECT_EQ(secondSaRemote, invoker_->GetSaRemote());
    EXPECT_EQ(invoker_->GetStartCallCount(), 2);
    sptr<IRemoteObject> expectedCallbackRemote = callbackRemote;
    EXPECT_EQ(invoker_->GetLastStartDto().callbackRemote, expectedCallbackRemote);
    EXPECT_EQ(invoker_->GetLastStartDto().analysisTypes, dto.analysisTypes);
    EXPECT_EQ(invoker_->GetLastStartDto().param, dto.param);
}

HWTEST_F(ActiveAnalysisManagerTest, SubmitTaskRollbackAllowsRetryAfterStartFailure, TestSize.Level1)
{
    auto callbackRemote = sptr<FakeRemoteObject>(new FakeRemoteObject(u"mock_callback"));
    StartActiveAnalysisDto dto = BuildStartDto(callbackRemote);
    int32_t firstResult = E_OK;
    int32_t secondResult = E_OK;
    sptr<IRemoteObject> firstSaRemote;
    sptr<IRemoteObject> secondSaRemote;

    invoker_->SetStartResult(MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR);
    EXPECT_EQ(manager_->SubmitTask(dto, firstResult, firstSaRemote), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR);

    invoker_->SetStartResult(E_OK);
    EXPECT_EQ(manager_->SubmitTask(dto, secondResult, secondSaRemote), E_OK);
    EXPECT_EQ(firstResult, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR);
    EXPECT_EQ(secondResult, E_OK);
    EXPECT_EQ(firstSaRemote, nullptr);
    EXPECT_EQ(secondSaRemote, invoker_->GetSaRemote());
    EXPECT_EQ(invoker_->GetStartCallCount(), 2);
}

HWTEST_F(ActiveAnalysisManagerTest, CancelTaskForwardsRequestWithoutLocalState, TestSize.Level1)
{
    StopActiveAnalysisDto dto = BuildStopDto();
    int32_t resultCode = -1;

    int32_t ret = manager_->CancelTask(dto, resultCode);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(resultCode, E_OK);
    EXPECT_EQ(invoker_->GetStopCallCount(), 1);
    EXPECT_EQ(invoker_->GetLastStopDto().analysisTypes, dto.analysisTypes);
    EXPECT_EQ(invoker_->GetLastStopDto().fileIds, dto.fileIds);
    EXPECT_EQ(invoker_->GetLastStopDto().param, dto.param);
}

HWTEST_F(ActiveAnalysisManagerTest, CancelTaskRejectsInvalidFileId, TestSize.Level1)
{
    StopActiveAnalysisDto dto = BuildStopDto();
    dto.fileIds = { "0" };
    int32_t resultCode = -1;

    int32_t ret = manager_->CancelTask(dto, resultCode);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(invoker_->GetStopCallCount(), 0);
}

HWTEST_F(ActiveAnalysisManagerTest, CancelTaskRejectsOversizedParam, TestSize.Level1)
{
    StopActiveAnalysisDto dto = BuildStopDto();
    dto.param.assign(MAX_ACTIVE_ANALYSIS_PARAM_LENGTH + 1, 'a');
    int32_t resultCode = -1;

    int32_t ret = manager_->CancelTask(dto, resultCode);

    EXPECT_EQ(ret, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(resultCode, MEDIA_LIBRARY_INVALID_PARAMETER_ERROR);
    EXPECT_EQ(invoker_->GetStopCallCount(), 0);
}
} // namespace OHOS::Media
