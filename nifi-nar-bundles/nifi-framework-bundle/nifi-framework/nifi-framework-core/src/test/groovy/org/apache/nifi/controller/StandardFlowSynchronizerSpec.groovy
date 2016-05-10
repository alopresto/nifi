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
package org.apache.nifi.controller

import org.apache.nifi.cluster.protocol.DataFlow
import org.apache.nifi.connectable.*
import org.apache.nifi.controller.label.Label
import org.apache.nifi.controller.queue.FlowFileQueue
import org.apache.nifi.groups.ProcessGroup
import org.apache.nifi.groups.RemoteProcessGroup
import org.apache.nifi.processor.Relationship
import org.apache.nifi.reporting.BulletinRepository
import spock.lang.Specification

class StandardFlowSynchronizerSpec extends Specification {

    def "test scaling positions based on flow encoding version"() {
        given: "three flows, one with no version, one with a version less than 1, and one with a version equal to 1"
        def controller = Mock FlowController
        def proposedFlow = Mock DataFlow
        def snippetManager = Mock SnippetManager
        def bulletinRepository = Mock BulletinRepository
        def flowFileQueue = Mock FlowFileQueue
        def testFlowBytes = new File(StandardFlowSynchronizerSpec.getResource('/conf/scale-positions-flow-0.7.0.xml').toURI()).bytes
        def versionedTestFlowBytes = new File(StandardFlowSynchronizerSpec.getResource('/conf/scale-positions-flow-versioned-0.7.0.xml').toURI()).bytes
        def lowVersionedTestFlowBytes = new File(StandardFlowSynchronizerSpec.getResource('/conf/scale-positions-flow-low-versioned-0.7.0.xml').toURI()).bytes
        def flowSynchronizer = new StandardFlowSynchronizer(null)
        def Map<String, Position> positionsById = [:]
        def Map<String, Positionable> positionableMocksById = [:]
        def Map<String, Connection> connectionMocksById = [:]
        def Map<String, List<Position>> bendPointsByConnectionId = [:]
        def rootGroupId = null

        when: "the flows are loaded, scale the positions for flows that are of a version less than 1.0"
        // synchronize the non-versioned flow, positions/bendpoints will be scaled
        flowSynchronizer.sync controller, proposedFlow, null
        // save off the scaled positions for comparison later
        def Map<String, Position> nullVersionScaledPositionsById = positionsById.clone()
        def Map<String, List<Position>> nullVersionScaledBendPointsByConnectionId = bendPointsByConnectionId.clone()
        // synchronize the versioned flow, positions/bendpoints should be unchanged
        flowSynchronizer.sync controller, proposedFlow, null
        // save off the scaled positions for comparison later
        def Map<String, Position> lowVersionScaledPositionsById = positionsById.clone()
        def Map<String, List<Position>> lowVersionScaledBendPointsByConnectionId = bendPointsByConnectionId.clone()
        // synchronize the versioned flow, positions/bendpoints should be unchanged
        flowSynchronizer.sync controller, proposedFlow, null
        // after this third invocation of flowSynchronizer, positionsById and bendPointsByConnectionId have their original component positions

        then: "establish interactions for the mocked collaborators of StandardFlowSynchronizer to store the ending positions of components"
        3 * controller.isInitialized() >> false
        _ * controller.rootGroupId >> rootGroupId
        _ * controller.getGroup(_) >> { String id -> positionableMocksById.get(id) }
        _ * controller.snippetManager >> snippetManager
        _ * controller.bulletinRepository >> bulletinRepository
        _ * controller./set.*/(*_)
        _ * controller.createProcessGroup(_) >> { String pgId ->
            if (positionableMocksById.isEmpty()) {
                rootGroupId = pgId
            }
            def processGroup = Mock(ProcessGroup)
            _ * processGroup.getIdentifier() >> pgId
            _ * processGroup.getPosition() >> { positionsById.get(pgId) }
            _ * processGroup.setPosition(_) >> { Position pos ->
                positionsById.put pgId, pos
            }
            _ * processGroup./(add|set).*/(*_)
            _ * processGroup.isEmpty() >> true
            _ * processGroup.isRootGroup() >> { pgId == rootGroupId }
            _ * processGroup.getConnectable(_) >> { String connId -> positionableMocksById.get(connId) }
            _ * processGroup.findAllPositionables() >> {
                positionableMocksById.values().forEach { Positionable p ->
                }
                positionableMocksById.values().toSet()
            }
            _ * processGroup.findAllConnections() >> {
                connectionMocksById.values().toList()
            }
            positionableMocksById.put(pgId, processGroup)
            return processGroup
        }

        _ * controller.createProcessor(_, _, _) >> { String type, String id, boolean firstTimeAdded ->
            def processor = Mock(ProcessorNode)
            _ * processor.getPosition() >> { positionsById.get(id) }
            _ * processor.setPosition(_) >> { Position pos ->
                positionsById.put id, pos
            }
            _ * processor./(add|set).*/(*_)
            _ * processor.getIdentifier() >> id
            _ * processor.getRelationship(_) >> { String n -> new Relationship.Builder().name(n).build() }
            positionableMocksById.put(id, processor)
            return processor
        }
        _ * controller.createFunnel(_) >> { String id ->
            def funnel = Mock(Funnel)
            _ * funnel.getPosition() >> { positionsById.get(id) }
            _ * funnel.setPosition(_) >> { Position pos ->
                positionsById.put id, pos
            }
            _ * funnel./(add|set).*/(*_)
            positionableMocksById.put id, funnel
            return funnel
        }
        _ * controller.createLabel(_, _) >> { String id, String text ->
            def l = Mock(Label)
            _ * l.getPosition() >> { positionsById.get(id) }
            _ * l.setPosition(_) >> { Position pos ->
                positionsById.put id, pos
            }
            _ * l./(add|set).*/(*_)
            positionableMocksById.put(id, l)
            return l
        }
        _ * controller./create.*Port/(_, _) >> { String id, String text ->
            def port = Mock(Port)
            _ * port.getPosition() >> { positionsById.get(id) }
            _ * port.setPosition(_) >> { Position pos ->
                positionsById.put id, pos
            }
            _ * port./(add|set).*/(*_)
            positionableMocksById.put(id, port)
            return port
        }
        _ * controller.createRemoteProcessGroup(_, _) >> { String id, String uri ->
            def rpg = Mock(RemoteProcessGroup)
            _ * rpg.getPosition() >> { positionsById.get(id) }
            _ * rpg.setPosition(_) >> { Position pos ->
                positionsById.put id, pos
            }
            _ * rpg./(add|set).*/(*_)
            _ * rpg.getOutputPort(_) >> { String rpgId -> positionableMocksById.get(rpgId) }
            _ * rpg.getIdentifier() >> id
            positionableMocksById.put(id, rpg)
            return rpg
        }
        _ * controller.createConnection(_, _, _, _, _) >> { String id, String name, Connectable source, Connectable destination, Collection<String> relationshipNames ->
            def connection = Mock(Connection)
            _ * connection.getIdentifier() >> id
            _ * connection.getBendPoints() >> {
                def bendpoints = bendPointsByConnectionId.get(id)
                return bendpoints
            }
            _ * connection.setBendPoints(_) >> { args ->
                // TODO Spock method matching here is doing something strange by providing a list of arguments to the method, rather than just the list of positions.
                // Need to keep an eye on this...
                def positions = args[0]
                bendPointsByConnectionId.put id, positions
            }
            _ * connection./set.*/(*_)
            _ * connection.flowFileQueue >> flowFileQueue
            connectionMocksById.put(id, connection)
            return connection
        }
        _ * controller.startProcessor(*_)
        _ * controller.startConnectable(_)
        _ * controller.enableControllerServices(_)
        _ * snippetManager.export() >> {
            [] as byte[]
        }
        _ * snippetManager.clear()
        3 * proposedFlow.flow >>> [testFlowBytes, lowVersionedTestFlowBytes, versionedTestFlowBytes]
        _ * proposedFlow.snippets >> {
            [] as byte[]
        }
        _ * flowFileQueue./set.*/(*_)
        _ * _.hashCode() >> 1
        0 * _ // no other mock calls allowed

        then: "verify that the flows with no version and major versions less than 1 are scaled, and that the flow with a version of 1.0 is not"
        positionsById.forEach { String id, Position position ->
            def scaledPosition = nullVersionScaledPositionsById.get(id)
            if (position.x != 0) {
                assert (position.x > 0) ? position.x < scaledPosition.x : position.x > scaledPosition.x
            }
            if (position.y != 0) {
                assert (position.y > 0) ? position.y < scaledPosition.y : position.y > scaledPosition.y
            }
        }
        positionsById.forEach { String id, Position position ->
            def scaledPosition = lowVersionScaledPositionsById.get(id)
            if (position.x != 0) {
                assert (position.x > 0) ? position.x < scaledPosition.x : position.x > scaledPosition.x
            }
            if (position.y != 0) {
                assert (position.y > 0) ? position.y < scaledPosition.y : position.y > scaledPosition.y
            }
        }
        bendPointsByConnectionId.forEach { String id, List<Position> positions ->
            positions.forEach { position ->
                def scaledBendPoints = nullVersionScaledBendPointsByConnectionId.get(id)
                scaledBendPoints.forEach { scaledPosition ->
                    if (position.x != 0) {
                        assert (position.x > 0) ? position.x < scaledPosition.x : position.x > scaledPosition.x
                    }
                    if (position.y != 0) {
                        assert (position.y > 0) ? position.y < scaledPosition.y : position.y > scaledPosition.y
                    }
                }
            }
        }
        bendPointsByConnectionId.forEach { String id, List<Position> positions ->
            positions.forEach { position ->
                def scaledBendPoints = lowVersionScaledBendPointsByConnectionId.get(id)
                scaledBendPoints.forEach { scaledPosition ->
                    if (position.x != 0) {
                        assert (position.x > 0) ? position.x < scaledPosition.x : position.x > scaledPosition.x
                    }
                    if (position.y != 0) {
                        assert (position.y > 0) ? position.y < scaledPosition.y : position.y > scaledPosition.y
                    }
                }
            }
        }
    }
}
