import org.apache.nifi.flowfile.FlowFile
import org.apache.nifi.processor.ProcessorInitializationContext
import org.apache.nifi.processor.io.StreamCallback
import org.apache.nifi.processors.standard.ListFile

import java.nio.charset.StandardCharsets

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
FlowFile flowFile = session.get()

if (flowFile == null) {
  return;
}

String directoryPath = "<no path set>"
String fileFilter = "<no filter set>"

flowFile = session.write(flowFile,
        { inputStream, outputStream ->
            // Assumes the entire content of the incoming flowfile is the directory path
            directoryPath = inputStream.text
            log.info("Directory path from flowfile: ${directoryPath}")

            // Retrieves an attribute and uses for the fileFilter
            fileFilter = flowFile.getAttribute('fileFilter')
            log.info("File filter from the flowfile: ${fileFilter}")

            ListFile listFile = new ListFile()
            log.info("ListFile properties: ${listFile.getProperties().entrySet().join(", ")}")

            context.setProperty(ListFile.DIRECTORY, directoryPath)
            context.setProperty(ListFile.FILE_FILTER, fileFilter)

            // TODO: All could be retrieved from flowfile attributes
            context.setProperty(ListFile.MIN_SIZE, "0B")
            context.setProperty(ListFile.MAX_SIZE, "1MB")
            context.setProperty(ListFile.MIN_AGE, "0MS")
            context.setProperty(ListFile.MAX_AGE, "365 days")
            context.setProperty(ListFile.RECURSE, "false")
            context.setProperty(ListFile.IGNORE_HIDDEN_FILES, "false")

            // Manually invoke onScheduled to set the file filter
            ProcessorInitializationContext initContext = [getIdentifier: { -> "mockId" }, getLogger: { -> log }, getControllerServiceLookup: { -> null }] as ProcessorInitializationContext
            listFile.initialize(initContext)
            listFile.onScheduled(context)

            // Retrieves all files (the null for min timestamp means all files are retrieved)
            def files = listFile.performListing(context, null)
//            def files = [[fileName: "file1.groovy"], [fileName: "file2.groovy"]]
            log.info("Retrieved files: ${files*.fileName.join(", ")}")

            // Collects the filename for each file and writes one per line to the flowfile content
            outputStream.write(files.collect { it.fileName }.join("\n").getBytes(StandardCharsets.UTF_8))
        } as StreamCallback)

flowFile = session.putAttribute(flowFile, 'directoryPath', directoryPath)
//flowFile = session.putAttribute(flowFile, 'fileFilter', fileFilter)
session.transfer(flowFile, REL_SUCCESS)