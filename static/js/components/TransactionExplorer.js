import React, { useState, useEffect } from 'react';
import { Network } from 'react-vis-network';
import { ArrowLeft, ArrowRight } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const TransactionExplorer = () => {
  const [history, setHistory] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(-1);
  const [loading, setLoading] = useState(false);
  const [graphData, setGraphData] = useState(null);
  const [transactionDetails, setTransactionDetails] = useState(null);

  const fetchNodeData = async (address) => {
    setLoading(true);
    try {
      const response = await fetch('/analyze_node/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `wallet_address=${address}`
      });
      const data = await response.json();
      if (data.status === 'success') {
        return data.data;
      }
      throw new Error(data.message);
    } catch (error) {
      console.error('Error fetching node data:', error);
      return null;
    } finally {
      setLoading(false);
    }
  };

  const handleNodeClick = async (node) => {
    const address = node.custom_properties?.address;
    if (!address) return;

    // Remove forward history if we're not at the end
    const newHistory = history.slice(0, currentIndex + 1);
    const newIndex = currentIndex + 1;

    // Add new address to history
    newHistory.push(address);
    setHistory(newHistory);
    setCurrentIndex(newIndex);

    // Fetch and display new data
    const nodeData = await fetchNodeData(address);
    if (nodeData) {
      setGraphData(nodeData.graph);
      setTransactionDetails(nodeData.analysis);
    }
  };

  const navigate = async (direction) => {
    const newIndex = direction === 'back' ? currentIndex - 1 : currentIndex + 1;
    if (newIndex >= 0 && newIndex < history.length) {
      setCurrentIndex(newIndex);
      const nodeData = await fetchNodeData(history[newIndex]);
      if (nodeData) {
        setGraphData(nodeData.graph);
        setTransactionDetails(nodeData.analysis);
      }
    }
  };

  return (
    <div className="flex flex-col space-y-4 w-full">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Transaction Explorer</CardTitle>
          <div className="flex space-x-2">
            <Button 
              variant="outline" 
              onClick={() => navigate('back')}
              disabled={currentIndex <= 0 || loading}
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back
            </Button>
            <Button 
              variant="outline" 
              onClick={() => navigate('forward')}
              disabled={currentIndex >= history.length - 1 || loading}
            >
              Forward
              <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-96 w-full relative">
            {loading && (
              <div className="absolute inset-0 bg-black/50 flex items-center justify-center text-white">
                Loading...
              </div>
            )}
            {graphData && (
              <Network
                graph={graphData}
                options={{
                  height: '100%',
                  width: '100%',
                  nodes: {
                    shape: 'dot',
                    size: 30,
                    font: {
                      size: 14
                    }
                  },
                  edges: {
                    arrows: 'to'
                  },
                  interaction: {
                    hover: true,
                    navigationButtons: true,
                    keyboard: true
                  }
                }}
                events={{
                  click: (event) => {
                    const { nodes } = event;
                    if (nodes.length > 0) {
                      handleNodeClick(nodes[0]);
                    }
                  }
                }}
              />
            )}
          </div>
        </CardContent>
      </Card>

      {transactionDetails && (
        <Card>
          <CardHeader>
            <CardTitle>Transaction Details</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm font-medium">Total Transactions</p>
                <p className="text-2xl">{transactionDetails.total_transactions}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Transaction Volume</p>
                <p className="text-2xl">{transactionDetails.transaction_volume.toFixed(4)} ETH</p>
              </div>
              <div>
                <p className="text-sm font-medium">Fraud Score</p>
                <p className="text-2xl">{transactionDetails.fraud_score}%</p>
              </div>
            </div>
            {transactionDetails.suspicious_activities.length > 0 && (
              <div className="mt-4">
                <p className="text-sm font-medium mb-2">Suspicious Activities</p>
                <ul className="list-disc pl-4">
                  {transactionDetails.suspicious_activities.map((activity, index) => (
                    <li key={index} className="text-sm text-red-500">{activity}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default TransactionExplorer;