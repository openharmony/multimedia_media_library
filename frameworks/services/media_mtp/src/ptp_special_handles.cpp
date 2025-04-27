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

#include "ptp_special_handles.h"

namespace OHOS {
namespace Media {
using namespace std;
shared_ptr<PtpSpecialHandles> PtpSpecialHandles::instance_ = nullptr;
mutex PtpSpecialHandles::mutex_;

shared_ptr<PtpSpecialHandles> PtpSpecialHandles::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = make_shared<PtpSpecialHandles>();
        }
    }
    return instance_;
}

PtpSpecialHandles::~PtpSpecialHandles()
{
    lock_guard<mutex> lock(mutex_);
    deletedHandleMap_.clear();
}

void PtpSpecialHandles::AddHandleToMap(uint32_t deletedHandle, uint32_t realHandle)
{
    lock_guard<mutex> lock(mutex_);
    deletedHandleMap_[deletedHandle] = realHandle;
}

uint32_t PtpSpecialHandles::HandleConvertToAdded(uint32_t deletedHandle) const
{
    lock_guard<mutex> lock(mutex_);
    auto it = deletedHandleMap_.find(deletedHandle);
    if (it != deletedHandleMap_.end()) {
        return it->second;
    } else {
        return deletedHandle;
    }
}

bool PtpSpecialHandles::FindRealHandle(uint32_t realHandle) const
{
    lock_guard<mutex> lock(mutex_);
    for (const auto& handlePair : deletedHandleMap_) {
        if (handlePair.second == realHandle) {
            return true;
        }
    }
    return false;
}

bool PtpSpecialHandles::FindDeletedHandle(int32_t deletedHandle) const
{
    lock_guard<mutex> lock(mutex_);
    auto it = deletedHandleMap_.find(deletedHandle);
    return it != deletedHandleMap_.end();
}

uint32_t PtpSpecialHandles::HandleConvertToDeleted(uint32_t realHandle) const
{
    lock_guard<mutex> lock(mutex_);
    for (auto& pair : deletedHandleMap_) {
        if (pair.second == realHandle) {
            return pair.first;
        }
    }
    return realHandle;
}

void PtpSpecialHandles::ClearDeletedHandles()
{
    lock_guard<mutex> lock(mutex_);
    deletedHandleMap_.clear();
}
} // namespace Media
} // namespace OHOS