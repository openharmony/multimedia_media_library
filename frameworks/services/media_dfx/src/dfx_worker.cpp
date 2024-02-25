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
#define MLOG_TAG "DfxWorker"

#include "dfx_worker.h"

#include <pthread.h>

#include "media_file_utils.h"
#include "media_log.h"
#include "dfx_manager.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "parameters.h"

using namespace std;
namespace OHOS {
namespace Media {
shared_ptr<DfxWorker> DfxWorker::dfxWorkerInstance_{nullptr};

shared_ptr<DfxWorker> DfxWorker::GetInstance()
{
    if (dfxWorkerInstance_ == nullptr) {
        dfxWorkerInstance_ = make_shared<DfxWorker>();
    }
    return dfxWorkerInstance_;
}

DfxWorker::DfxWorker()
{
    shortTime_ = stoi(system::GetParameter("persist.multimedia.medialibrary.dfx.shorttime", FIVE_MINUTE)) *
        TO_MILLION * ONE_MINUTE;
    longTime_ = stoi(system::GetParameter("persist.multimedia.medialibrary.dfx.longtime", ONE_DAY)) * ONE_MINUTE *
        ONE_MINUTE;
}

DfxWorker::~DfxWorker()
{
}

void DfxWorker::Init()
{
    MEDIA_INFO_LOG("init");
    cycleThread_ = thread(bind(&DfxWorker::InitCycleThread, this));
    isEnd_ = false;
}

void DfxWorker::InitCycleThread()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    lastReportTime_ = prefs->GetLong(LAST_REPORT_TIME, 0);
    while (!isEnd_) {
        DfxManager::GetInstance()->HandleFiveMinuteTask();
        if (MediaFileUtils::UTCTimeSeconds() - lastReportTime_ > longTime_) {
            MEDIA_INFO_LOG("Report Xml");
            lastReportTime_ = DfxManager::GetInstance()->HandleReportXml();
            prefs->PutLong(LAST_REPORT_TIME, lastReportTime_);
            prefs->Flush();
        }
        this_thread::sleep_for(chrono::milliseconds(shortTime_));
    }
}

void DfxWorker::End()
{
    isEnd_ = true;
}
} // namespace Media
} // namespace OHOS