import mongoose from "mongoose";

const portDetailSchema = new mongoose.Schema({
  port: Number,
  open: Boolean,
  service: String,
  risk: String,
  description: String,
});
                   
const scanResultSchema = new mongoose.Schema({
  host: { type: String, required: true },
  scanTime: { type: Date, default: Date.now },
  ports: { type: Map, of: portDetailSchema, required: true },
  summary: {
    total: Number,
    open: Number,
    riskAssessment: String,
  },
  recommendations: [String],

  // New timespan field in milliseconds
  timespan: { type: Number, default: 0 },
});

const PortScan = mongoose.model("PortScan", scanResultSchema);

export default PortScan;
