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

#define MLOG_TAG "ActiveAnalysisManager"

#include "active_analysis_manager.h"

#include <algorithm>

#include "media_analysis_proxy.h"
#include "media_library_error_code.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS::Media::AnalysisData {
namespace {
constexpr int32_t MEDIA_ANALYSIS_SERVICE_SAID = 10120;
constexpr int32_t SUPPORTED_ACTIVE_ANALYSIS_TYPE_BEGIN = static_cast<int32_t>(ANALYSIS_TYPE_START);
constexpr int32_t SUPPORTED_ACTIVE_ANALYSIS_TYPE_END = static_cast<int32_t>(ANALYSIS_TYPE_END);
constexpr size_t SUPPORTED_ACTIVE_ANALYSIS_TYPE_COUNT = static_cast<size_t>(
    SUPPORTED_ACTIVE_ANALYSIS_TYPE_END - SUPPORTED_ACTIVE_ANALYSIS_TYPE_BEGIN - 1);
constexpr size_t MAX_ACTIVE_ANALYSIS_FILE_ID_COUNT = 100;
constexpr size_t MAX_ACTIVE_ANALYSIS_PARAM_LENGTH = 500;

bool IsPositiveNumericString(const std::string &value)
{
    return !value.empty() &&
        std::all_of(value.begin(), value.end(), ::isdigit) &&
        value.find_first_not_of('0') != std::string::npos;
}

bool AreValidFileIds(const std::vector<std::string> &fileIds)
{
    CHECK_AND_RETURN_RET_LOG(fileIds.size() <= MAX_ACTIVE_ANALYSIS_FILE_ID_COUNT, false,
        "Active analysis fileIds size exceeds limit, size: %{public}zu, max: %{public}zu",
        fileIds.size(), MAX_ACTIVE_ANALYSIS_FILE_ID_COUNT);
    return std::all_of(fileIds.begin(), fileIds.end(), [](const auto &fileId) {
        return IsPositiveNumericString(fileId);
    });
}

bool IsValidParam(const std::string &param)
{
    return param.size() <= MAX_ACTIVE_ANALYSIS_PARAM_LENGTH;
}
} // namespace

class MediaAnalysisRemoteInvoker final : public ActiveAnalysisRemoteInvoker {
public:
    sptr<IRemoteObject> GetSaRemote() const override
    {
        auto remote = MediaAnalysisProxy::GetRemoteObject(
            static_cast<int32_t>(IMediaAnalysisService::ActivateServiceType::START_ACTIVE_ANALYSIS));
        CHECK_AND_RETURN_RET_LOG(remote != nullptr, nullptr,
            "Failed to get media analysis service remote, said: %{public}d", MEDIA_ANALYSIS_SERVICE_SAID);
        return remote;
    }

    int32_t StartActiveAnalysis(const StartActiveAnalysisDto &dto) const override
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option(MessageOption::TF_ASYNC);
        MediaAnalysisProxy proxy(nullptr);
        CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(proxy.GetDescriptor()), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write start active analysis interface token");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32Vector(dto.analysisTypes), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write start active analysis types, size: %{public}zu", dto.analysisTypes.size());
        CHECK_AND_RETURN_RET_LOG(data.WriteStringVector(dto.fileIds), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write start active analysis fileIds, size: %{public}zu", dto.fileIds.size());
        CHECK_AND_RETURN_RET_LOG(data.WriteString(dto.param), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write start active analysis param, size: %{public}zu", dto.param.size());
        CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(dto.callbackRemote), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write start active analysis callback remote");
        bool sendRet = MediaAnalysisProxy::SendTransactCmd(
            static_cast<int32_t>(IMediaAnalysisService::ActivateServiceType::START_ACTIVE_ANALYSIS),
            data, reply, option);
        CHECK_AND_RETURN_RET_LOG(sendRet, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to send start active analysis transact");
        return E_OK;
    }

    int32_t StopActiveAnalysis(const StopActiveAnalysisDto &dto) const override
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option(MessageOption::TF_ASYNC);
        MediaAnalysisProxy proxy(nullptr);
        CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(proxy.GetDescriptor()), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write stop active analysis interface token");
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32Vector(dto.analysisTypes), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write stop active analysis types, size: %{public}zu", dto.analysisTypes.size());
        CHECK_AND_RETURN_RET_LOG(data.WriteStringVector(dto.fileIds), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write stop active analysis fileIds, size: %{public}zu", dto.fileIds.size());
        CHECK_AND_RETURN_RET_LOG(data.WriteString(dto.param), MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to write stop active analysis param, size: %{public}zu", dto.param.size());
        bool sendRet = MediaAnalysisProxy::SendTransactCmd(
            static_cast<int32_t>(IMediaAnalysisService::ActivateServiceType::STOP_ACTIVE_ANALYSIS),
            data, reply, option);
        CHECK_AND_RETURN_RET_LOG(sendRet, MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
            "Failed to send stop active analysis transact");
        return E_OK;
    }
};

ActiveAnalysisManager &ActiveAnalysisManager::GetInstance()
{
    static ActiveAnalysisManager manager(std::make_shared<MediaAnalysisRemoteInvoker>());
    return manager;
}

ActiveAnalysisManager::ActiveAnalysisManager(std::shared_ptr<ActiveAnalysisRemoteInvoker> invoker)
    : invoker_(std::move(invoker))
{
}

int32_t ActiveAnalysisManager::SubmitTask(
    const StartActiveAnalysisDto &dto, int32_t &resultCode, sptr<IRemoteObject> &saRemote)
{
    saRemote = nullptr;
    CHECK_AND_RETURN_RET_LOG(AreSupportedTypes(dto.analysisTypes), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Unsupported active analysis types, size: %{public}zu", dto.analysisTypes.size());
    CHECK_AND_RETURN_RET_LOG(AreValidFileIds(dto.fileIds), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Invalid active analysis fileIds, size: %{public}zu", dto.fileIds.size());
    CHECK_AND_RETURN_RET_LOG(IsValidParam(dto.param), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Invalid active analysis param, size: %{public}zu", dto.param.size());
    CHECK_AND_RETURN_RET_LOG(dto.callbackRemote != nullptr, resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Active analysis callback remote is nullptr");

    resultCode = invoker_->StartActiveAnalysis(dto);
    CHECK_AND_RETURN_RET_LOG(resultCode == E_OK, resultCode,
        "Failed to start active analysis, resultCode: %{public}d", resultCode);
    saRemote = invoker_->GetSaRemote();
    CHECK_AND_RETURN_RET_LOG(saRemote != nullptr, resultCode = MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR,
        "Failed to get active analysis sa remote after start");
    return resultCode;
}

int32_t ActiveAnalysisManager::CancelTask(const StopActiveAnalysisDto &dto, int32_t &resultCode)
{
    CHECK_AND_RETURN_RET_LOG(AreSupportedTypes(dto.analysisTypes), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Unsupported active analysis types for stop, size: %{public}zu", dto.analysisTypes.size());
    CHECK_AND_RETURN_RET_LOG(AreValidFileIds(dto.fileIds), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Invalid stop active analysis fileIds, size: %{public}zu", dto.fileIds.size());
    CHECK_AND_RETURN_RET_LOG(IsValidParam(dto.param), resultCode = MEDIA_LIBRARY_INVALID_PARAMETER_ERROR,
        "Invalid stop active analysis param, size: %{public}zu", dto.param.size());
    resultCode = invoker_->StopActiveAnalysis(dto);
    CHECK_AND_PRINT_LOG(resultCode == E_OK, "Failed to stop active analysis, resultCode: %{public}d", resultCode);
    return resultCode;
}

bool ActiveAnalysisManager::AreSupportedTypes(const std::vector<int32_t> &analysisTypes)
{
    CHECK_AND_RETURN_RET_LOG(!analysisTypes.empty(), false, "Active analysis types is empty");
    CHECK_AND_RETURN_RET_LOG(analysisTypes.size() <= SUPPORTED_ACTIVE_ANALYSIS_TYPE_COUNT, false,
        "Active analysis types size exceeds supported count, size: %{public}zu, max: %{public}zu",
        analysisTypes.size(), SUPPORTED_ACTIVE_ANALYSIS_TYPE_COUNT);
    for (auto analysisType : analysisTypes) {
        CHECK_AND_RETURN_RET_LOG(IsSupportedType(analysisType), false,
            "Unsupported active analysis type: %{public}d", analysisType);
    }
    return true;
}

bool ActiveAnalysisManager::IsSupportedType(int32_t analysisType)
{
    return analysisType > SUPPORTED_ACTIVE_ANALYSIS_TYPE_BEGIN &&
        analysisType < SUPPORTED_ACTIVE_ANALYSIS_TYPE_END;
}
} // namespace OHOS::Media::AnalysisData
