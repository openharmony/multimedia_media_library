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

export type ValueType = number | string | boolean;

export namespace dataSharePredicates {
    export class DataSharePredicates {
        static { loadLibrary("data_share_predicates"); }
        private nativePtr: long = 0;

        constructor(nativePtr: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = nativePtr;
            }
        }
        getNativePtr(): long {
            return this.nativePtr;
        }
        native static create():DataSharePredicates;
        native equalTo(field: string, value: ValueType):DataSharePredicates;
        native orderByDesc(field: string):DataSharePredicates;
        native orderByAsc(field: string):DataSharePredicates;
        native and():DataSharePredicates;
        native limit(total: number, offset: number):DataSharePredicates;
        native lessThan(field: string, value: ValueType): DataSharePredicates;
        native like(field: string, value: string): DataSharePredicates;
        native endWrap(): DataSharePredicates;
        native greaterThanOrEqualTo(field: string, value: ValueType): DataSharePredicates;
        native contains(field: string, value: string): DataSharePredicates;
        native or(): DataSharePredicates;
        native beginWrap(): DataSharePredicates;
        native greaterThan(field: string, value: ValueType): DataSharePredicates;
    }
}

export function mockDataSharePredicates(): dataSharePredicates.DataSharePredicates {
    console.println("hello DataSharePredicates")
    let datashare = dataSharePredicates.DataSharePredicates.create();
    let result = datashare.equalTo("123", "abc")
    result.equalTo("456", true)
    result.equalTo("789", 123)
    result = datashare.orderByDesc("758")
    result = datashare.orderByAsc("668")
    result = datashare.and()
    result.limit(10, 10)
    console.println("result from native")

    datashare.lessThan("boy", "jack").lessThan("boy2", 120).lessThan("boy3", false);

    datashare.like("girl", "rose");

    datashare.endWrap();

    datashare.greaterThanOrEqualTo("cat", "higer").greaterThanOrEqualTo("cat2", 12.9)
        .greaterThanOrEqualTo("cat3", true);

    datashare.contains("name", "rose");

    datashare.or();

    datashare.beginWrap();

    datashare.greaterThan("age", "100").greaterThanOrEqualTo("age2", 150.01)
        .greaterThanOrEqualTo("age3", true);

    return datashare;
}
