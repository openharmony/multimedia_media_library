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

#ifndef FRAMEWORKS_UTILS_INCLUDE_ANALYSIS_ALBUM_OPERATION_DATA_UTILS_H
#define FRAMEWORKS_UTILS_INCLUDE_ANALYSIS_ALBUM_OPERATION_DATA_UTILS_H

#include <algorithm>
#include <string>
#include <vector>

#include "analysis_album_attribute_const.h"

namespace OHOS::Media {
struct AnalysisAlbumOperationData {
    std::vector<std::string> addNickNames;
    std::vector<std::string> removeNickNames;
};
} // namespace OHOS::Media

namespace OHOS::Media::AnalysisAlbumOperationDataUtils {
template<typename OperationType>
inline void RemoveChangeOperation(std::vector<OperationType> &operations, OperationType operation)
{
    operations.erase(std::remove(operations.begin(), operations.end(), operation), operations.end());
}

inline void RemovePendingNickNames(std::vector<std::string> &pendingNickNames,
    const std::vector<std::string> &nickNames)
{
    pendingNickNames.erase(std::remove_if(pendingNickNames.begin(), pendingNickNames.end(),
        [&nickNames](const std::string &pendingNickName) {
            return std::find(nickNames.begin(), nickNames.end(), pendingNickName) != nickNames.end();
        }), pendingNickNames.end());
}

inline void AppendPendingNickNames(std::vector<std::string> &pendingNickNames,
    const std::vector<std::string> &nickNames)
{
    for (const auto &nickName : nickNames) {
        if (std::find(pendingNickNames.begin(), pendingNickNames.end(), nickName) == pendingNickNames.end()) {
            pendingNickNames.push_back(nickName);
        }
    }
}

template<typename OperationData, typename OperationType>
inline void RefreshNickNameOperations(std::vector<OperationType> &operations, const OperationData &operationData,
    OperationType addOperation, OperationType removeOperation)
{
    RemoveChangeOperation(operations, addOperation);
    RemoveChangeOperation(operations, removeOperation);
    if (!operationData.addNickNames.empty()) {
        operations.push_back(addOperation);
    }
    if (!operationData.removeNickNames.empty()) {
        operations.push_back(removeOperation);
    }
}

template<typename OperationData, typename OperationType>
inline void UpdateAddNickNameOperationData(OperationData &operationData, std::vector<OperationType> &operations,
    OperationType addOperation, OperationType removeOperation, const std::vector<std::string> &values)
{
    RemovePendingNickNames(operationData.removeNickNames, values);
    AppendPendingNickNames(operationData.addNickNames, values);
    RefreshNickNameOperations(operations, operationData, addOperation, removeOperation);
}

template<typename OperationData, typename OperationType>
inline void UpdateRemoveNickNameOperationData(OperationData &operationData, std::vector<OperationType> &operations,
    OperationType addOperation, OperationType removeOperation, const std::vector<std::string> &values)
{
    RemovePendingNickNames(operationData.addNickNames, values);
    AppendPendingNickNames(operationData.removeNickNames, values);
    RefreshNickNameOperations(operations, operationData, addOperation, removeOperation);
}

template<typename OperationData, typename OperationType>
inline void SetNickNameOperationData(OperationData &operationData, std::vector<OperationType> &operations,
    const std::string &type, OperationType addOperation, OperationType removeOperation,
    const std::vector<std::string> &values)
{
    if (type == ANALYSIS_ALBUM_OP_ADD) {
        UpdateAddNickNameOperationData(operationData, operations, addOperation, removeOperation, values);
        return;
    }
    if (type == ANALYSIS_ALBUM_OP_REMOVE) {
        UpdateRemoveNickNameOperationData(operationData, operations, addOperation, removeOperation, values);
    }
}
} // namespace OHOS::Media::AnalysisAlbumOperationDataUtils

#endif // FRAMEWORKS_UTILS_INCLUDE_ANALYSIS_ALBUM_OPERATION_DATA_UTILS_H
