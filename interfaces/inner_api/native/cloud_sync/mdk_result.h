/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIA_CLOUD_SYNC_RESULT_H
#define OHOS_MEDIA_CLOUD_SYNC_RESULT_H

#include "mdk_error.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MDKResult {
public:
    // 返回结果是否成功
    bool IsSuccess() const
    {
        if (error_.HasError()) {
            return false;
        }
        return true;
    }
    void SetDKError(MDKError error)
    {
        error_ = error;
    }
    MDKError GetDKError() const
    {
        return error_;
    }

protected:
    MDKError error_;
};

class EXPORT MDKRecordOperResult : public MDKResult {
public:
    MDKRecordOperResult()
    {}
    MDKRecordOperResult(MDKLocalErrorCode code)
    {
        error_.SetLocalError(code);
    }

public:
    void SetDKRecord(const MDKRecord &record)
    {
        record_ = record;
    }
    MDKRecord GetDKRecord() const
    {
        return record_;
    }

private:
    MDKRecord record_;
};
} // namespace OHOS::Media::CloudSync
#endif