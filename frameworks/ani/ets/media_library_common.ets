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

import { dataSharePredicates } from "@ohos.data.dataSharePredicates";
import { PhotoSubtype, NotifyType } from "./media_library_enum.ets";

export class Context {}

export interface MediaChangeRequest {}

export interface PhotoProxy {}

export interface FetchOptions {
    fetchColumns: Array<string>;
    predicates: dataSharePredicates.DataSharePredicates;
}

export class FetchOptionsInner implements FetchOptions {
    fetchColumns: Array<string> = {};
    predicates: dataSharePredicates.DataSharePredicates = new dataSharePredicates.DataSharePredicates(0);
}

export interface PhotoCreateOptions {
    subtype?: PhotoSubtype;
    cameraShotKey?: string;
}

export class PhotoCreateOptionsInner implements PhotoCreateOptions {
    subtype?: PhotoSubtype | undefined;
    cameraShotKey?: string | undefined;
}

export interface CreateOptions {
    title?: string;
    subtype?: PhotoSubtype;
}

export class CreateOptionsInner implements CreateOptions {
    title?: string | undefined;
    subtype?: PhotoSubtype | undefined;
}

export interface ChangeData {
    type: NotifyType;
    uris: Array<string>;
    extraUris: Array<string>;
}
